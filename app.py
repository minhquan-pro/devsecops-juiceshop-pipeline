"""Local single-user educational UI; Python standard library only."""
from __future__ import annotations

import argparse
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from juicesec.core import scan, analyze_source, html_report
from juicesec.ai_classifier import VulnerabilityAIClassifier, FEATURE_METADATA

ROOT = Path(__file__).resolve().parent
CSRF_TOKEN = secrets.token_urlsafe(32)
SCAN_LOCK = threading.Lock()
REPORT = {}
REPORT_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Request paths and submitted code are intentionally not logged.
        pass

    def permitted_host(self):
        return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

    def send_data(self, status, data, content_type="application/json; charset=utf-8"):
        raw = data.encode("utf-8") if isinstance(data, str) else data
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def json_data(self, status, obj):
        self.send_data(status, json.dumps(obj, ensure_ascii=False))

    def do_GET(self):
        if not self.permitted_host():
            return self.json_data(403, {"error": "Use the 127.0.0.1 origin printed by the server"})
        path = urlsplit(self.path).path
        assets = {"/": ("index.html", "text/html; charset=utf-8"),
                  "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                  "/style.css": ("style.css", "text/css; charset=utf-8")}
        if path in assets:
            name, mime = assets[path]
            return self.send_data(200, (ROOT / "static" / name).read_bytes(), mime)
        if path == "/api/session":
            return self.json_data(200, {"csrf": CSRF_TOKEN})
        if path == "/api/knowledge":
            return self.send_data(200, (ROOT/"data"/"knowledge.json").read_bytes())
        if path == "/api/ai":
            clf = VulnerabilityAIClassifier()
            checksum_path = ROOT / "models" / "model_checksum.sha256"
            model_path = ROOT / "models" / "vuln_classifier.joblib"
            sha256_hash = checksum_path.read_text(encoding="utf-8").strip() if checksum_path.exists() else ""
            integrity_valid = clf.verify_model_integrity(model_path) if model_path.exists() else False

            bench_5k_path = ROOT / "evidence" / "synthetic_5k_benchmark.json"
            bench_5k = json.loads(bench_5k_path.read_text(encoding="utf-8")) if bench_5k_path.exists() else {}

            bench_prod_path = ROOT / "evidence" / "ai_benchmark.json"
            bench_prod = json.loads(bench_prod_path.read_text(encoding="utf-8")) if bench_prod_path.exists() else {}

            ai_info = {
                "model_mode": clf.mode,
                "model_name": clf.model_name,
                "model_path": str(model_path.relative_to(ROOT)) if model_path.exists() else None,
                "sha256_checksum": sha256_hash,
                "integrity_valid": integrity_valid,
                "anti_tampering": "Enforced (SHA-256 Checksum Guard against Deserialization RCE)",
                "features_count": len(FEATURE_METADATA),
                "features": FEATURE_METADATA,
                "benchmark_production": bench_prod.get("holdout_evaluation", {}),
                "benchmark_production_cv": bench_prod.get("cross_validation_5_folds", {}).get("summary", {}),
                "benchmark_5k": bench_5k,
                "asymmetric_security_policy": {
                    "critical_high_downgrade": "STRICTLY FORBIDDEN (Never downgrade deterministic AST Critical/High)",
                    "low_info_escalation": "Permitted if AI confidence >= 0.85",
                    "score_fusion": "Bayesian Logit Odds: sigmoid(0.7*logit(rule) + 0.3*logit(global_ai))"
                }
            }
            return self.json_data(200, ai_info)
        if path in ("/api/report", "/api/report.html"):
            with REPORT_LOCK:
                saved = dict(REPORT)
            if not saved:
                return self.json_data(404, {"error": "No report yet"})
            if path.endswith(".html"):
                return self.send_data(200, html_report(saved), "text/html; charset=utf-8")
            return self.json_data(200, saved)
        self.json_data(404, {"error": "Not found"})

    def do_POST(self):
        global REPORT
        expected_origin = f"http://127.0.0.1:{self.server.server_port}"
        if (not self.permitted_host() or self.headers.get("Origin") != expected_origin
                or not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), CSRF_TOKEN)):
            return self.json_data(403, {"error": "Origin or CSRF token rejected"})
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            return self.json_data(415, {"error": "application/json required"})
        if self.headers.get("Transfer-Encoding"):
            return self.json_data(400, {"error": "Transfer encoding is unsupported"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 250000:
                return self.json_data(413, {"error": "Invalid request size"})
            self.connection.settimeout(5)
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError("JSON object required")
            path = urlsplit(self.path).path
            if path == "/api/scan":
                if not SCAN_LOCK.acquire(blocking=False):
                    return self.json_data(409, {"error": "A scan is already running"})
                try:
                    if type(data.get("active", False)) is not bool:
                        raise ValueError("active must be boolean")
                    if type(data.get("openapi_fuzz", False)) is not bool:
                        raise ValueError("openapi_fuzz must be boolean")
                    if type(data.get("ai_hybrid", True)) is not bool:
                        raise ValueError("ai_hybrid must be boolean")
                    ai_hybrid = data.get("ai_hybrid", True)
                    report = scan(
                        data.get("target", ""),
                        data.get("active", False),
                        data.get("openapi_fuzz", False),
                        analyze_client=ai_hybrid
                    )
                    client_code = report.pop("client_source_sample", "")
                    if ai_hybrid:
                        clf = VulnerabilityAIClassifier()
                        raw_findings = report.get("findings", [])
                        rescored_findings = clf.rescore_ast_findings(raw_findings, client_code)
                        report["findings"] = rescored_findings
                        eval_snippet = client_code if client_code.strip() else "/* DAST Network Assessment: No client-side scripts extracted */"
                        ai_telemetry = clf.get_detailed_explanation(eval_snippet)
                        report["ai_telemetry"] = ai_telemetry

                        findings_count = len(rescored_findings)
                        records_count = len(report.get("records", []))
                        errors_count = len(report.get("errors", []))
                        total_checks = records_count + errors_count
                        if total_checks == 0:
                            total_checks = max(findings_count, 1)

                        bayesian_conf = ai_telemetry.get("bayesian_confidence")
                        if bayesian_conf is not None:
                            risk_percent = int(round(float(bayesian_conf) * 100))
                        else:
                            risk_percent = int(round((findings_count / total_checks) * 100))
                        risk_percent = max(0, min(100, risk_percent))

                        report["ai_gauge"] = {
                            "risk_percent": risk_percent,
                            "findings": findings_count,
                            "total": total_checks
                        }
                finally:
                    SCAN_LOCK.release()
            elif path == "/api/source":
                source_code = data.get("source", "")
                filename = data.get("filename", "snippet.txt")
                raw_findings = analyze_source(source_code, filename)
                clf = VulnerabilityAIClassifier()
                rescored_findings = clf.rescore_ast_findings(raw_findings, source_code)
                ai_telemetry = clf.get_detailed_explanation(source_code)
                findings_count = len(rescored_findings)
                total_checks = max(findings_count, 1)
                bayesian_conf = ai_telemetry.get("bayesian_confidence")
                if bayesian_conf is not None:
                    risk_percent = int(round(float(bayesian_conf) * 100))
                else:
                    risk_percent = int(round((findings_count / total_checks) * 100))
                risk_percent = max(0, min(100, risk_percent))
                report = {
                    "schema_version": "1.1",
                    "mode": "sast_regex_ast_union",
                    "target": "submitted source",
                    "findings": rescored_findings,
                    "ai_telemetry": ai_telemetry,
                    "ai_gauge": {
                        "risk_percent": risk_percent,
                        "findings": findings_count,
                        "total": total_checks
                    },
                    "limits": [
                        "Static flow analysis only; no exploit confirmation",
                        "Findings carry status needs_review until an analyst validates them"
                    ]
                }
            elif path == "/api/ai/predict":
                source = data.get("source", "")
                clf = VulnerabilityAIClassifier()
                explanation = clf.get_detailed_explanation(source)
                return self.json_data(200, explanation)
            else:
                return self.json_data(404, {"error": "Not found"})
            with REPORT_LOCK:
                REPORT = report
            self.json_data(200, report)
        except (ValueError, UnicodeDecodeError, TypeError, OSError) as exc:
            self.json_data(400, {"error": str(exc)[:160]})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
        print(f"JuiceSec Analyzer: http://127.0.0.1:{server.server_port}", flush=True)
        print("Single-user educational server. Ctrl+C to stop.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
