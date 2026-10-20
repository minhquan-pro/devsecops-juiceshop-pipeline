# Verification and Reproducibility Guide (VERIFY.md)

This document provides a concise, step-by-step reproduction guide for the JuiceSec Analyzer, its test suite, evaluation benchmarks, and quality gates.

---

## 1. Prerequisites and Environment

- **Python Version**: Python 3.10 or higher.
- **Runtime Dependencies**: **Zero external dependencies** (`requirements.txt` contains zero runtime packages; only standard library modules such as `http.server`, `http.client`, `urllib`, `ast`, `re`, `json`, `hashlib`, `hmac`, and `unittest` are used).
- **Development Tooling (Optional)**: Listed in `requirements-dev.txt` (`bandit`, `semgrep`) for CI security auditing.

Verify zero runtime dependencies:
```bash
python -c "import pathlib; lines = [l.strip() for l in pathlib.Path('requirements.txt').read_text().splitlines()]; pkgs = [l for l in lines if l and not l.startswith('#')]; assert not pkgs, f'unexpected deps: {pkgs}'; print('zero-dependency guarantee holds')"
```

---

## 2. Test Suite Execution

Run the complete unit test suite (automated tests covering Python AST and JavaScript token/regex flow rules, network collection, loopback target pinning, case-insensitive redaction, and IDOR regression cases):

```bash
python -m unittest discover -s tests -v
```

Expected output:
- `Ran 63 tests in ~1.4s`
- `OK`

---

## 3. Evaluation Benchmark and Evidence Generation

Run `evaluate.py` to:
1. Re-run unit tests and write results to `evidence/tests.txt`.
2. Compute cryptographic SHA-256 hashes and validate schemas for `data/corpus.json` (40 snippets), `data/holdout.json` (26 snippets), and `data/external_corpus.json` (40 out-of-sample public CVE snippets under zero-tuning).
3. Compute the confusion matrix (TP, FP, TN, FN), Precision, Recall, and F1-score for all datasets.
4. Record scanner rule integrity hashes (`juicesec/core.py`, `juicesec/astscan.py`) ensuring frozen evaluation conditions.
5. Spin up an internal fixture server and execute 20 benchmark runs (excluding warm-up) to compute latency statistics (median, min, max, p95).
6. Output structured JSON artifacts: `evidence/validation.json`, `evidence/corpus-results.json`, `evidence/holdout-results.json`, `evidence/external-results.json`, `evidence/fixture-report.json`, and `evidence/fixture-report.html`.

```bash
python evaluate.py
```

---

## 4. Quality Gate Enforcement

Validate that current metrics satisfy the CI quality floors:

```bash
python scan_gate.py \
  --require-tests-pass \
  --min-f1 0.85 \
  --min-precision 0.85 \
  --min-recall 0.85 \
  --min-holdout-f1 0.85 \
  --min-external-f1 0.50 \
  --max-p95-ms 500
```

Expected output:
- `[gate] unit tests 63 passed OK`
- `[gate] corpus.f1 1.0000 >= 0.8500 OK`
- `[gate] corpus.precision 1.0000 >= 0.8500 OK`
- `[gate] corpus.recall 1.0000 >= 0.8500 OK`
- `[gate] holdout.f1 1.0000 >= 0.8500 OK`
- `[gate] external.f1 0.5625 >= 0.5000 OK`
- `[gate] p95 latency ...ms <= 500.0ms OK`
- `[gate] all quality thresholds satisfied`
- Exit code: 0

---

## 5. Web Interface and CLI

### Local Web Dashboard
Start the lightweight web UI:
```bash
python app.py
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser to inspect the knowledge base, run the analyzer's Python-AST or JavaScript token/regex SAST checks on submitted snippets, and view scan reports.

### Command Line Interface
The CLI accepts either a local HTTP target or a source file:
```bash
python cli.py --target http://127.0.0.1:5000 --out evidence/local-scan.json
python cli.py --source path/to/example.js --out evidence/source-report.json
```

---

## 6. Live Exploit Scenarios and Evidence Redaction

### Running Exploit Scenarios Against OWASP Juice Shop
When a local OWASP Juice Shop instance is running (e.g., at `http://127.0.0.1:3000` via Docker):
```bash
python labs/juice_shop_exploits.py --target http://127.0.0.1:3000
```

Security controls:
- **Strict loopback origin isolation**: rejects external hosts, non-http schemes, userinfo, path, query, fragment, and invalid ports.
- **Robust IDOR verification**: verifies authenticated identity and proves basket 2 belongs to a distinct user. Yields `not_reproduced` on same-owner or access-denied responses, and `inconclusive` on unverified identity or malformed responses.

### Evidence Redaction Pass
Sanitize generated evidence before publishing or committing:
```bash
python labs/redact_evidence.py evidence/
```
Case-insensitively masks JWTs, Bearer tokens, HTTP credential headers, sensitive URL query parameters, and compound keys (`access_token`, `refresh_token`, `api_key`, `client_secret`, `password`, `cookie`).

---

## 7. Failure Analysis & Academic Head-to-Head Baseline

### Failure Analysis Artifact Generation
Generate confusion matrices per rule across internal and external corpora, characterizing structural failure modes (Lexical Shadowing, Constant Concat, Dynamic Dispatch, Inter-procedural Discontinuity):
```bash
python labs/gen_error_analysis.py
```
Outputs: `evidence/error_analysis.json` and formal analysis in `docs/ERROR_ANALYSIS.md`.

### Head-to-Head Baseline Benchmark (JuiceSec vs. Semgrep vs. Bandit)
Execute empirical 3D comparison (Detection Efficacy, Latency, and Resource Footprint):
```bash
python labs/benchmark_baseline.py
```
Outputs: `evidence/benchmark_baseline.json` and formatted report in `evidence/appendix_c_benchmark.txt`.

### Report Appendices Generation
Generate report appendices B (Ground-Truth Corpora) and C (Empirical Baseline Benchmark):
```bash
python labs/gen_report_appendices.py
```

---

## 8. Academic Documentation & Theoretical Grounding

- **Threat Model**: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) details the STRIDE threat model, DFD Level 0/1 diagrams, trust boundaries (TB-1 to TB-4), and mitigation traceability matrix.
- **Scanner Limitations**: [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) grounds static analysis undecidability in Rice's Theorem (1953) and the Halting Problem, analyzing 5 structural failure classes with a comparative matrix against Semgrep and CodeQL.
- **Failure Analysis**: [`docs/ERROR_ANALYSIS.md`](docs/ERROR_ANALYSIS.md) breaks down false negatives and false positives with architectural root cause derivations.

---

## 9. Scope and Scientific Integrity Notes

1. **Dual Evaluation Scope**:
   - `data/corpus.json` (40 snippets) and `data/holdout.json` (26 snippets) serve as internal regression testing suites.
   - `data/external_corpus.json` (40 snippets) evaluates generalization against real-world CVEs under strict zero-tuning protocol.
2. **Structural Analyzer Scope**: The lightweight AST/lexical analyzer is engineered for single-file, zero-dependency, sub-millisecond execution. It trades inter-procedural completeness for near-zero runtime latency and zero deployment friction.
