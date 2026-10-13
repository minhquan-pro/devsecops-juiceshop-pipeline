"""Quality gate for the JuiceSec pipeline.

Reads the machine-readable evidence produced by ``evaluate.py`` and fails the CI
stage when a metric drops below an agreed threshold. This keeps the security
scanner itself under continuous measurement instead of trusting a static claim.

Usage::

    python scan_gate.py --min-f1 0.55 --min-recall 0.55 --min-precision 0.55
    python scan_gate.py --max-p95-ms 500 --require-tests-pass

The thresholds are intentionally conservative: they are set just below the
delivered baseline (F1 0.5946) so the gate catches *regressions* without turning
red on harmless noise. Raise them as the engine improves.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_EVIDENCE = ROOT / "evidence" / "validation.json"


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
    parser.add_argument("--max-p95-ms", type=float, default=None)
    parser.add_argument("--require-tests-pass", action="store_true")
    args = parser.parse_args()

    summary = load_summary(args.evidence)
    corpus = summary.get("corpus", {})
    holdout = summary.get("holdout", {})
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
    # The holdout set is the honest generalization check: it is never used to
    # tune rules, so its floor is the strongest statement in this gate.
    if holdout:
        metric("holdout.f1", holdout.get("f1"), args.min_holdout_f1)

    if args.max_p95_ms is not None:
        p95 = benchmark.get("p95_nearest_rank")
        if p95 is None:
            failures.append("benchmark.p95_nearest_rank is missing (got None)")
        elif p95 > args.max_p95_ms:
            failures.append(f"p95 latency {p95:.1f}ms exceeds the ceiling {args.max_p95_ms:.1f}ms")
        else:
            print(f"[gate] p95 latency {p95:.1f}ms <= {args.max_p95_ms:.1f}ms OK")

    if failures:
        print("\n[gate] FAILED:", file=sys.stderr)
        for item in failures:
            print(f"  - {item}", file=sys.stderr)
        return 1
    print("\n[gate] all quality thresholds satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
