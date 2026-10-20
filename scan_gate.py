"""Quality gate for the JuiceSec pipeline.

Reads the machine-readable evidence produced by ``evaluate.py`` and fails the CI
stage when a metric drops below an agreed threshold. This keeps the security
scanner itself under continuous measurement instead of trusting a static claim.

Usage::

    python scan_gate.py --min-f1 0.55 --min-recall 0.55 --min-precision 0.55
    python scan_gate.py --max-p95-ms 500 --require-tests-pass

The thresholds are intentionally conservative: they are set just below the
delivered baseline (corpus F1=1.0, holdout F1=1.0 for v1.1) so the gate catches
*regressions* without turning red on harmless noise. Raise them as the engine improves.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_EVIDENCE = ROOT / "evidence" / "validation.json"
DEFAULT_AI_EVIDENCE = ROOT / "evidence" / "ai_benchmark.json"


def load_summary(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"evidence not found: {path}. Run evaluate.py first.")
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail CI when scan quality regresses")
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--min-f1", type=float, default=0.0)
    parser.add_argument("--min-precision", type=float, default=0.0)
    parser.add_argument("--min-recall", type=float, default=0.0)
    parser.add_argument("--min-holdout-f1", type=float, default=0.0)
    parser.add_argument("--min-external-f1", type=float, default=0.0)
    parser.add_argument("--min-external-recall", type=float, default=0.0)
    parser.add_argument("--max-p95-ms", type=float, default=None)
    parser.add_argument("--require-tests-pass", action="store_true")
    parser.add_argument("--require-ai-gate", action="store_true", help="Enforce quality floors on ML model benchmark")
    parser.add_argument("--ai-evidence", type=Path, default=DEFAULT_AI_EVIDENCE)
    parser.add_argument("--min-ai-f1", type=float, default=0.0)
    parser.add_argument("--min-ai-auc", type=float, default=0.0)
    parser.add_argument("--min-ai-cv-f1", type=float, default=0.0, help="Floor for 5-Fold Cross-Validation F1-score (Default: 0.70 if --require-ai-gate)")
    parser.add_argument("--min-ai-cv-auc", type=float, default=0.0, help="Floor for 5-Fold Cross-Validation ROC-AUC (Default: 0.75 if --require-ai-gate)")
    parser.add_argument("--max-ai-brier-score", type=float, default=None, help="Ceiling for Brier calibration loss (Default: 0.15 if --require-ai-gate)")
    parser.add_argument("--max-ai-latency-ms", type=float, default=None)
    args = parser.parse_args()

    summary = load_summary(args.evidence)
    corpus = summary.get("corpus", {})
    holdout = summary.get("holdout", {})
    external = summary.get("external", {})
    benchmark = summary.get("benchmark", {})
    tests = summary.get("unit_tests", {})

    failures: list[str] = []

    def metric(name: str, value, floor: float) -> None:
        if value is None:
            failures.append(f"{name} is missing (got None)")
        elif value < floor:
            failures.append(f"{name} {value:.4f} is below the floor {floor:.4f}")
        else:
            print(f"[gate] {name} {value:.4f} >= {floor:.4f} OK")

    if args.require_tests_pass and not tests.get("successful"):
        failures.append(
            f"unit tests failed: {tests.get('failures')} failure(s), {tests.get('errors')} error(s)"
        )
    elif args.require_tests_pass:
        print(f"[gate] unit tests {tests.get('run')} passed OK")

    metric("corpus.f1", corpus.get("f1"), args.min_f1)
    metric("corpus.precision", corpus.get("precision"), args.min_precision)
    metric("corpus.recall", corpus.get("recall"), args.min_recall)
    # The holdout set is an internal synthetic micro-benchmark used as a regression
    # floor to verify that rule changes do not cause unforeseen regressions.
    if holdout:
        metric("holdout.f1", holdout.get("f1"), args.min_holdout_f1)
    # The external dataset evaluates zero-tuning out-of-sample generalizability
    # across real public CVE snippets.
    if external and args.min_external_f1 > 0:
        metric("external.f1", external.get("f1"), args.min_external_f1)
    if external and args.min_external_recall > 0:
        metric("external.recall", external.get("recall"), args.min_external_recall)

    if args.max_p95_ms is not None:
        p95 = benchmark.get("p95_nearest_rank")
        if p95 is None:
            failures.append("benchmark.p95_nearest_rank is missing (got None)")
        elif p95 > args.max_p95_ms:
            failures.append(f"p95 latency {p95:.1f}ms exceeds the ceiling {args.max_p95_ms:.1f}ms")
        else:
            print(f"[gate] p95 latency {p95:.1f}ms <= {args.max_p95_ms:.1f}ms OK")

    # AI Quality Gate verification
    if (
        args.require_ai_gate
        or args.min_ai_f1 > 0
        or args.min_ai_auc > 0
        or args.min_ai_cv_f1 > 0
        or args.min_ai_cv_auc > 0
        or args.max_ai_latency_ms is not None
    ):
        if not args.ai_evidence.is_file():
            failures.append(f"AI evidence not found: {args.ai_evidence}. Run labs/train_ai_model.py first.")
        else:
            try:
                ai_data = json.loads(args.ai_evidence.read_text(encoding="utf-8"))
                holdout_eval = ai_data.get("holdout_evaluation", {})
                ai_f1 = holdout_eval.get("f1")
                ai_auc = holdout_eval.get("roc_auc")
                latency_info = ai_data.get("latency_benchmark", {})
                ai_lat = latency_info.get("mean_latency_ms")

                if args.min_ai_f1 > 0 or args.require_ai_gate:
                    floor_f1 = args.min_ai_f1 if args.min_ai_f1 > 0 else 0.80
                    metric("ai_model.holdout_f1", ai_f1, floor_f1)

                if args.min_ai_auc > 0 or args.require_ai_gate:
                    floor_auc = args.min_ai_auc if args.min_ai_auc > 0 else 0.85
                    metric("ai_model.roc_auc", ai_auc, floor_auc)

                # Cross-Validation rigor check (Audit Bypass Prevention: Mandate CV floors when --require-ai-gate is enabled)
                cv_summary = ai_data.get("cross_validation_5_folds", {}).get("summary", {})
                cv_f1 = cv_summary.get("f1", {}).get("mean") if isinstance(cv_summary.get("f1"), dict) else None
                cv_auc = cv_summary.get("roc_auc", {}).get("mean") if isinstance(cv_summary.get("roc_auc"), dict) else None

                if args.min_ai_cv_f1 > 0 or args.require_ai_gate:
                    floor_cv_f1 = args.min_ai_cv_f1 if args.min_ai_cv_f1 > 0 else 0.70
                    metric("ai_model.cv_f1", cv_f1, floor_cv_f1)

                if args.min_ai_cv_auc > 0 or args.require_ai_gate:
                    floor_cv_auc = args.min_ai_cv_auc if args.min_ai_cv_auc > 0 else 0.75
                    metric("ai_model.cv_auc", cv_auc, floor_cv_auc)

                # Calibration check: Brier score loss
                holdout_brier = holdout_eval.get("brier_score")
                if holdout_brier is not None and (args.require_ai_gate or args.max_ai_brier_score is not None):
                    ceiling_brier = args.max_ai_brier_score if args.max_ai_brier_score is not None else 0.15
                    if holdout_brier > ceiling_brier:
                        failures.append(f"ai_model.holdout_brier {holdout_brier:.4f} exceeds ceiling {ceiling_brier:.4f}")
                    else:
                        print(f"[gate] ai_model.holdout_brier {holdout_brier:.4f} <= {ceiling_brier:.4f} OK")

                if args.max_ai_latency_ms is not None and ai_lat is not None:
                    if ai_lat > args.max_ai_latency_ms:
                        failures.append(f"AI latency {ai_lat:.2f}ms exceeds the ceiling {args.max_ai_latency_ms:.1f}ms")
                    else:
                        print(f"[gate] AI latency {ai_lat:.2f}ms <= {args.max_ai_latency_ms:.1f}ms OK")
            except Exception as e:
                failures.append(f"Error parsing AI benchmark evidence: {e}")

    if failures:
        print("\n[gate] FAILED:", file=sys.stderr)
        for item in failures:
            print(f"  - {item}", file=sys.stderr)
        return 1
    print("\n[gate] all quality thresholds satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
