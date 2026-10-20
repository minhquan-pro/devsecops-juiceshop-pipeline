"""Reproduce tests, labelled micro-corpus results and fixture benchmark.

These measurements describe the bundled synthetic data, not Juice Shop.
"""
import io
import json
import platform
import statistics
import threading
import time
import hashlib
import unittest
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from juicesec.core import analyze_source, scan, html_report
from tests.fixture_server import Fixture

ROOT = Path(__file__).resolve().parent
PY_IDS = {"H-DES-A", "H-XXE-A", "H-XXE-B"}


def validate_dataset(path: Path) -> tuple[list[dict], dict]:
    """Load, hash, and validate schema integrity and uniqueness of a dataset."""
    raw_bytes = path.read_bytes()
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    data = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Dataset at {path} must be a JSON list of objects")

    seen_ids: set[str] = set()
    duplicate_ids: list[str] = []
    required_keys = {"id", "source", "positive"}

    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Item #{idx} in {path.name} is not a dict")
        missing = required_keys - set(item.keys())
        if missing:
            raise ValueError(f"Item #{idx} in {path.name} missing required keys: {sorted(missing)}")
        if not isinstance(item["id"], str) or not item["id"].strip():
            raise ValueError(f"Item #{idx} in {path.name} has invalid 'id'")
        if not isinstance(item["source"], str):
            raise ValueError(f"Item #{idx} ({item['id']}) has non-string 'source'")
        if not isinstance(item["positive"], bool):
            raise ValueError(f"Item #{idx} ({item['id']}) has non-bool 'positive'")

        item_id = item["id"].strip()
        if item_id in seen_ids:
            duplicate_ids.append(item_id)
        seen_ids.add(item_id)

    meta = {
        "file": path.name,
        "sha256": sha256,
        "count": len(data),
        "schema_valid": True,
        "duplicate_ids": duplicate_ids,
    }
    return data, meta


def measure(items, suffix=".js"):
    """Score the analyzer over a corpus, returning the confusion matrix and rows."""
    matrix = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    records = []
    for item in items:
        filename = item.get("filename")
        lang = item.get("language")
        if not filename:
            ext = ".py" if (lang == "python" or item["id"] in PY_IDS) else suffix
            filename = item["id"] + ext
        elif lang == "python" and not filename.endswith(".py"):
            filename = filename + ".py"

        findings = analyze_source(item["source"], filename)
        predicted = bool(findings)
        actual = item["positive"]
        category = ("tp" if actual else "fp") if predicted else ("fn" if actual else "tn")
        matrix[category] += 1
        records.append(
            dict(item, predicted=predicted, category=category, rule_ids=[f["rule_id"] for f in findings])
        )
    return matrix, records


def main():
    out = ROOT / "evidence"
    out.mkdir(exist_ok=True)
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    (out / "tests.txt").write_text(stream.getvalue(), encoding="utf-8")

    corpus, corpus_meta = validate_dataset(ROOT / "data" / "corpus.json")
    holdout, holdout_meta = validate_dataset(ROOT / "data" / "holdout.json")

    external_path = ROOT / "data" / "external_corpus.json"
    external = None
    external_meta = None
    ext_matrix = None
    ext_records = None
    if external_path.is_file():
        external, external_meta = validate_dataset(external_path)
        ext_matrix, ext_records = measure(external)

    corpus_ids = {item["id"] for item in corpus}
    holdout_ids = {item["id"] for item in holdout}
    overlap_ids = sorted(corpus_ids & holdout_ids)

    matrix, records = measure(corpus)
    hold_matrix, hold_records = measure(holdout)

    def metrics(m):
        tp, fp, tn, fn = [m[k] for k in ("tp", "fp", "tn", "fn")]
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        return {
            "count": tp + fp + tn + fn,
            **m,
            "precision": precision,
            "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision and recall else None,
        }

    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    target = f"http://127.0.0.1:{server.server_port}"
    try:
        scan(target)  # one excluded warm-up
        timings = []
        for _ in range(20):
            start = time.perf_counter()
            sample = scan(target)
            timings.append((time.perf_counter() - start) * 1000)
        active = scan(target, True)
    finally:
        server.shutdown()
        server.server_close()
        worker.join()

    datasets_provenance = {
        "corpus": corpus_meta,
        "holdout": holdout_meta,
    }
    if external_meta:
        datasets_provenance["external"] = external_meta

    rule_hashes = {
        "juicesec/core.py": hashlib.sha256((ROOT / "juicesec" / "core.py").read_bytes()).hexdigest(),
        "juicesec/astscan.py": hashlib.sha256((ROOT / "juicesec" / "astscan.py").read_bytes()).hexdigest(),
    }

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "scope": (
            "Internal synthetic regression floors (corpus, holdout) and external out-of-sample CVE validation. "
            "Real Juice Shop runs are tracked in evidence/juice-exploits.json."
        ),
        "engine": "line_regex + inter-procedural Python AST taint tracker + token/flow JS AST (see juicesec/astscan.py)",
        "rule_integrity_hashes": rule_hashes,
        "provenance": {
            "datasets": datasets_provenance,
            "id_overlap": overlap_ids,
            "note": (
                "Holdout is an internal synthetic micro-benchmark curated for regression testing. "
                "External corpus consists of out-of-sample public CVE snippets evaluated under zero tuning."
            ),
        },
        "unit_tests": {
            "run": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "successful": result.wasSuccessful(),
        },
        "corpus": metrics(matrix),
        "holdout": metrics(hold_matrix),
        "external": metrics(ext_matrix) if ext_matrix else None,
        "benchmark": {
            "runs": 20,
            "warmups_excluded": 1,
            "requests_per_run": 5,
            "unit": "ms",
            "median": statistics.median(timings),
            "minimum": min(timings),
            "maximum": max(timings),
            "p95_nearest_rank": sorted(timings)[18],
            "raw": timings,
        },
    }
    artifacts = [
        ("validation.json", summary),
        ("corpus-results.json", records),
        ("holdout-results.json", hold_records),
        ("fixture-report.json", active),
    ]
    if ext_records:
        artifacts.append(("external-results.json", ext_records))

    for name, data in artifacts:
        (out / name).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    (out/"fixture-report.html").write_text(html_report(active),encoding="utf-8")
    print(json.dumps(summary,ensure_ascii=False,indent=2))
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__": main()
