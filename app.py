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
                    report = scan(data.get("target", ""), data.get("active", False))
                finally:
                    SCAN_LOCK.release()
            elif path == "/api/source":
                report = {"schema_version": "1.1", "mode": "sast_regex_ast_union", "target": "submitted source",
                          "findings": analyze_source(data.get("source", ""), data.get("filename", "snippet.txt")),
                          "limits": ["Static flow analysis only; no exploit confirmation",
                                     "Findings carry status needs_review until an analyst validates them"]}
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
