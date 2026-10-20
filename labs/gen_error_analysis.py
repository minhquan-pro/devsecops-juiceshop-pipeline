"""Generate comprehensive per-rule confusion matrix and failure mode analysis.

This script diagnoses scanner limitations and trade-offs, formalizing:
- Per-rule Precision, Recall, and F1 across evaluated corpora.
- The 4 structural failure modes (Lexical Shadowing, Constant Concat, Dynamic Dispatch, Inter-procedural Discontinuity).
- Generates evidence/error_analysis.json.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from juicesec.core import analyze_source
PY_IDS = {"H-DES-A", "H-XXE-A", "H-XXE-B"}

# Canonical mapping of rule prefixes / categories
RULE_CATEGORIES = {
    "XSS": ["H-XSS", "SAST-AST-XSS", "SAST-AST-TRUST"],
    "SQLI": ["H-SQLI", "SAST-AST-SQL"],
    "IDOR_BAC": ["H-IDOR", "SAST-AST-BAC"],
    "JWT": ["H-JWT", "SAST-AST-JWT"],
    "MISC_CMD_DESER": ["H-DES-A", "H-XXE-A", "H-XXE-B", "SAST-AST-EVAL", "SAST-AST-CMD", "SAST-AST-PATH", "SAST-AST-SSRF", "SAST-AST-DESER", "SAST-AST-XXE", "SAST-AST-CSRF"],
}

# 4 Classical Failure Mode Case Studies for Academic Analysis
FAILURE_MODE_CASES = [
    {
        "id": "FM-01-SHADOWING",
        "name": "Lexical Shadowing & Variable Aliasing (False Positive)",
        "mode": "Mode 1: Lexical Shadowing",
        "description": "Inner block re-declares and sanitizes an identifier, but intra-file syntactic scan links sink to the tainted outer-scope identifier.",
        "sample_code": (
            "function handleRequest(req, res) {\n"
            "    const input = req.query.data;\n"
            "    if (isValid(input)) {\n"
            "        const input = sanitizeText(req.query.data);\n"
            "        res.send('<div>' + input + '</div>');\n"
            "    }\n"
            "}"
        ),
        "expected": "BENIGN (False Positive if flagged without scope shadowing resolution)",
        "root_cause": "The token-based JS scanner flattens lexical scope trees into a single symbol-assignment map, ignoring block-scoped variable shadowing (let/const shadowing in child AST scopes)."
    },
    {
        "id": "FM-02-CONST-CONCAT",
        "name": "Safe Constant Literal Concatenation (False Positive)",
        "mode": "Mode 2: Safe Constant Concatenation",
        "description": "Constructed query using purely compile-time constant string literals flagged by naive SQL concatenation rules.",
        "sample_code": (
            "const TABLE = 'products';\n"
            "const DEFAULT_FILTER = 'WHERE active = 1';\n"
            "const sql = 'SELECT * FROM ' + TABLE + ' ' + DEFAULT_FILTER;\n"
            "db.query(sql);"
        ),
        "expected": "BENIGN (False Positive if flagged without constant folding)",
        "root_cause": "AST matcher flags binary operator (+) on SQL strings without evaluating whether all operand nodes resolve to immutable string literals (lack of abstract interpretation/constant propagation)."
    },
    {
        "id": "FM-03-DYNAMIC-DISPATCH",
        "name": "Dynamic Property Dispatch & Indirect Invocation (False Negative)",
        "mode": "Mode 3: Dynamic Property Dispatch",
        "description": "Taint flow channeled through dynamic object property lookup or callback table, evading direct function call pattern matching.",
        "sample_code": (
            "const sinks = { render: (data) => element.innerHTML = data };\n"
            "const action = req.query.action || 'render';\n"
            "sinks[action](req.query.payload);"
        ),
        "expected": "VULNERABLE (False Negative because sinks[action]() is an indirect computed call)",
        "root_cause": "Intra-procedural AST matcher only inspects statically named MemberExpression and CallExpression nodes, failing to resolve computed properties or dynamic function dispatch."
    },
    {
        "id": "FM-04-INTER-PROCEDURAL",
        "name": "Inter-procedural & Cross-Module Discontinuity (False Negative)",
        "mode": "Mode 4: Inter-procedural Taint Dissipation",
        "description": "Source of taint is ingested in an Express controller, passed to a utility service class, and executed in an unparameterized database query in a separate file.",
        "sample_code": (
            "// controller.js\n"
            "const UserService = require('./services/userService');\n"
            "app.get('/user', (req, res) => {\n"
            "    UserService.findUserRaw(req.query.id);\n"
            "});\n"
            "// services/userService.js\n"
            "class UserService {\n"
            "    static findUserRaw(id) {\n"
            "        return db.query('SELECT * FROM users WHERE id = ' + id);\n"
            "    }\n"
            "}"
        ),
        "expected": "VULNERABLE (False Negative if analyzed per-file independently)",
        "root_cause": "JuiceSec analyzes files in total isolation (intra-file scope), lacking an inter-procedural Call Graph (CG) and cross-module Taint Flow Graph (TFG)."
    }
]


def compute_ruleset_hash() -> dict[str, str]:
    """Compute SHA-256 of analyzer code files to ensure provenance and zero-tuning."""
    hashes = {}
    for filename in ["astscan.py", "core.py"]:
        p = ROOT / "juicesec" / filename
        if p.exists():
            hashes[filename] = hashlib.sha256(p.read_bytes()).hexdigest()
    return hashes


def calculate_metrics(matrix: dict[str, int]) -> dict[str, float | None]:
    tp, fp, tn, fn = matrix["tp"], matrix["fp"], matrix["tn"], matrix["fn"]
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def analyze_corpus_detailed(dataset_path: Path) -> dict:
    if not dataset_path.exists():
        return {}
    items = json.loads(dataset_path.read_text(encoding="utf-8"))
    overall = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    category_matrices: dict[str, dict[str, int]] = {
        cat: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for cat in RULE_CATEGORIES
    }
    sample_diagnostics = []

    for item in items:
        item_id = item["id"]
        source = item["source"]
        actual_vuln = item["positive"]
        lang = item.get("language")
        filename = item.get("filename")
        if not filename:
            ext = ".py" if (lang == "python" or item_id in PY_IDS) else ".js"
            filename = item_id + ext
        elif lang == "python" and not filename.endswith(".py"):
            filename = filename + ".py"

        findings = analyze_source(source, filename)
        predicted_vuln = bool(findings)

        category = ("tp" if actual_vuln else "fp") if predicted_vuln else ("fn" if actual_vuln else "tn")
        overall[category] += 1

        matched_rules = [f["rule_id"] for f in findings]

        # Categorize per vulnerability type
        sample_category = None
        for cat_name, prefixes in RULE_CATEGORIES.items():
            if any(item_id.startswith(p.split("-")[0]) or p in item_id for p in prefixes):
                sample_category = cat_name
                break
        if not sample_category:
            if "SQL" in item_id:
                sample_category = "SQLI"
            elif "XSS" in item_id:
                sample_category = "XSS"
            elif "IDOR" in item_id or "BAC" in item_id:
                sample_category = "IDOR_BAC"
            elif "JWT" in item_id:
                sample_category = "JWT"
            else:
                sample_category = "MISC_CMD_DESER"

        if sample_category in category_matrices:
            cat_m = category_matrices[sample_category]
            cat_m[category] += 1

        sample_diagnostics.append({
            "id": item_id,
            "category": sample_category,
            "actual_positive": actual_vuln,
            "predicted_positive": predicted_vuln,
            "result_type": category,
            "matched_rules": matched_rules,
            "rationale": item.get("rationale", "")
        })

    per_rule_metrics = {
        cat: calculate_metrics(mat) for cat, mat in category_matrices.items()
    }

    return {
        "dataset_name": dataset_path.name,
        "sample_count": len(items),
        "overall_metrics": calculate_metrics(overall),
        "per_category_metrics": per_rule_metrics,
        "diagnostics": sample_diagnostics
    }


def main() -> int:
    evidence_dir = ROOT / "evidence"
    evidence_dir.mkdir(exist_ok=True)

    ruleset_hashes = compute_ruleset_hash()
    corpus_analysis = analyze_corpus_detailed(ROOT / "data" / "corpus.json")
    holdout_analysis = analyze_corpus_detailed(ROOT / "data" / "holdout.json")

    external_analysis = {}
    external_path = ROOT / "data" / "external_corpus.json"
    if external_path.exists():
        external_analysis = analyze_corpus_detailed(external_path)

    report = {
        "metadata": {
            "title": "JuiceSec Static Analyzer Error & Failure Mode Analysis",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "ruleset_sha256": ruleset_hashes,
            "methodology": "Confusion Matrix Analysis (TP/FP/TN/FN) with 4-Mode Failure Diagnosis"
        },
        "datasets": {
            "corpus": corpus_analysis,
            "holdout": holdout_analysis,
            "external_corpus": external_analysis,
        },
        "structural_failure_modes": FAILURE_MODE_CASES
    }

    out_file = evidence_dir / "error_analysis.json"
    out_file.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] Successfully generated error analysis artifact at {out_file.relative_to(ROOT)}")
    print(f"    - Corpus samples: {corpus_analysis.get('sample_count', 0)} (F1={corpus_analysis.get('overall_metrics', {}).get('f1')})")
    print(f"    - Holdout samples: {holdout_analysis.get('sample_count', 0)} (F1={holdout_analysis.get('overall_metrics', {}).get('f1')})")
    if external_analysis:
        print(f"    - External samples: {external_analysis.get('sample_count', 0)} (F1={external_analysis.get('overall_metrics', {}).get('f1')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
