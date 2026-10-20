"""Batch entry point; writes a JSON report and an escaped HTML report."""
import argparse
import json
from pathlib import Path
from juicesec.core import scan, analyze_source, html_report

p = argparse.ArgumentParser(description="JuiceSec local educational analyzer")
m = p.add_mutually_exclusive_group(required=True)
m.add_argument("--target")
m.add_argument("--source", type=Path)
p.add_argument("--active", action="store_true", help="Add one SQL syntax error probe in the local lab")
p.add_argument("--openapi-fuzz", action="store_true", help="Discover endpoints from /api-docs/ and fuzz them")
p.add_argument("--out", type=Path, default=Path("evidence/report.json"))
a = p.parse_args()
if a.target:
    result = scan(a.target, a.active, a.openapi_fuzz)
else:
    if a.source.stat().st_size > 200000:
        p.error("Source exceeds 200000 bytes")
    result = {"schema_version": "1.3", "mode": "sast_regex_ast_union", "target": a.source.name,
              "findings": analyze_source(a.source.read_text(encoding="utf-8"), a.source.name),
              "limits": ["Static flow analysis only; no exploit confirmation",
                         "Findings carry status needs_review until an analyst validates them"]}
a.out.parent.mkdir(parents=True, exist_ok=True)
a.out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
a.out.with_suffix(".html").write_text(html_report(result), encoding="utf-8")
print(a.out)
