# THREAT MODEL: JuiceSec Pipeline

## 1. Executive Summary & System Scope

JuiceSec is a dual-mode application security assessment system designed for educational DevSecOps pipelines. It integrates:
1. **Static AST Analysis (`juicesec.astscan`):** Intra-procedural Python and JavaScript syntax tree inspection for OWASP Top 10 vulnerability patterns (SQLi, XSS, IDOR, Hardcoded JWT/Secrets, Security Misconfigurations).
2. **Dynamic Active Probing (`juicesec.core` & `labs.juice_shop_exploits`):** Controlled HTTP-level security verification targeting local instances of OWASP Juice Shop.
3. **Automated Quality Gate (`scan_gate.py`):** CI/CD pipeline enforcement evaluating scan thresholds, precision, recall, and evidence integrity.

This threat model applies the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to identify security risks inherent to running automated scanner workflows within CI/CD and developer environments.

---

## 2. Trust Boundaries & Assumptions

### 2.1 Explicit Trust Boundaries

| Boundary | Description | Enforcement Mechanism |
| :--- | :--- | :--- |
| **TB-1: Network Egress & Target Boundary** | Isolation between the scanner runtime and network targets. Dynamic probes MUST ONLY communicate with designated local loopback instances. | Strict URL parsing in [`validate_target()`](labs/juice_shop_exploits.py:44). Only `localhost`, `127.0.0.1`, `::1` allowed. Outbound internet egress rejected. |
| **TB-2: Code Ingestion Boundary** | Untrusted source code files fed into the static analyzer. | Read-only file ingestion; strictly parsed via Python standard [`ast.parse()`](juicesec/astscan.py:100) and regex tokenizers. Never executed (`eval()`, `exec()`, or `importlib` prohibited). |
| **TB-3: Input Stream & Payload Boundary** | Size and format limits on HTTP responses and file reads. | Bounded reads (`MAX_BODY = 65536` bytes), HTTP timeout clamping (3.0s - 10.0s). |
| **TB-4: Evidence & Secret Boundary** | Handling sensitive credentials, session tokens, and scan logs. | Automated sanitization via [`labs/redact_evidence.py`](labs/redact_evidence.py:1) before persisting JSON/HTML reports to disk or CI artifacts. |

### 2.2 System Assumptions
- The CI/CD runner host or local development machine has an untampered Python 3.10+ standard library.
- The OWASP Juice Shop target running on `localhost:3000` is ephemeral, isolated within container namespaces, and contains synthetic dummy vulnerability data.

---

## 3. Data Flow Diagrams (DFD)

### 3.1 DFD Level 0 (Context Diagram)

```
                     +---------------------------------------+
                     |         Developer / CI Pipeline       |
                     +---------------------------------------+
                                    |         ^
                       Source Code  |         | Scan Reports & Gates
                       & CLI Args   v         | (HTML / JSON / Exit Codes)
                     +---------------------------------------+
                     |                                       |
                     |         JuiceSec Scanner Core         |
                     |                                       |
                     +---------------------------------------+
                            |                         ^
              HTTP Probes / |                         | HTTP Responses /
              Exploit Reqs  v                         | Error Traces
                     +---------------------------------------+
                     |   [TB-1] OWASP Juice Shop (Target)    |
                     +---------------------------------------+
```

### 3.2 DFD Level 1 (Decomposed Component Flows)

```
[Untrusted Codebase]
        |
        v (TB-2: Static Code Ingestion)
[AST Scanner Engine] ---> (Syntax Parsing ast.parse) ---> [Finding Matcher]
                                                                |
                                                                v
                                                      [Raw Vulnerability List]
                                                                |
[Dynamic Target URL]                                            v
        |                                             [Evidence Sanitizer]
        v (TB-1: Loopback Check)                                | (TB-4: Redaction)
[DAST Probe Engine]  ---> (HTTP Payloads)                       v
        |                                             [Sanitized Scan Report]
        v                                                       |
[Juice Shop Target]                                             v
        |                                             [CI Quality Gate]
        +---> (HTTP 200/500 Responses) ---> [Parser]            |
                                                                v
                                                        [Pipeline Exit Code]
```

---

## 4. STRIDE Threat Analysis & Mitigations

### 4.1 Spoofing (Identity & Target Spoofing)
- **Threat S1: Target Redirection & SSRF via DNS Rebinding**
  - *Scenario:* Malicious configuration passes a target URL resolving to an external server or internal cloud metadata service (`http://169.254.169.254/`).
  - *Risk:* High. Scanner acts as an unintentional scanning proxy or SSRF vector.
  - *Mitigation:* [`validate_target()`](labs/juice_shop_exploits.py:44) strictly enforces hostnames `localhost`, `127.0.0.1`, and `[::1]`. Reject all remote IPs, private RFC1918 subnets, and cloud metadata addresses.
- **Threat S2: Scanner Agent Spoofing in Evidence**
  - *Scenario:* Injection of falsified tool identifiers or forged timestamps in generated artifacts.
  - *Risk:* Low.
  - *Mitigation:* Evidence generation records git commit SHA, ISO UTC timestamps, and SHA-256 digests of rulesets.

### 4.2 Tampering (Data & Integrity Corruption)
- **Threat T1: Arbitrary File Ingestion & Code Tampering**
  - *Scenario:* Analyzed code attempts directory traversal (`../../etc/passwd`) or overwrites scanner files.
  - *Risk:* Medium.
  - *Mitigation:* Target paths are strictly opened in `r` (read-only) text mode within resolved directory boundaries.
- **Threat T2: Corpus Poisoning & Benchmark Gaming**
  - *Scenario:* Modifying ground-truth test datasets (`data/corpus.json`, `data/holdout.json`) to artificially inflate precision/recall.
  - *Risk:* High (Academic & Audit Integrity).
  - *Mitigation:* Automated SHA-256 integrity verification (`evidence/checksums.sha256`) and frozen out-of-sample datasets evaluated with `--zero-tuning`.

### 4.3 Repudiation (Disputing Scan Results)
- **Threat R1: Non-Reproducible Scan Reports**
  - *Scenario:* Findings generated on one run cannot be reproduced due to environment nondeterminism or undocumented dynamic state.
  - *Risk:* Medium.
  - *Mitigation:* Complete capture of HTTP request lines, headers, sanitized response bodies, and AST line numbers. Deterministic sorting of scan findings before serialization.

### 4.4 Information Disclosure (Leakage of Secrets)
- **Threat I1: Secret Leakage in Scan Artifacts & CI Logs**
  - *Scenario:* DAST probes capture real authorization tokens, admin passwords, or SQL connection strings from Juice Shop, printing them to GitHub Actions logs or committed HTML reports.
  - *Risk:* High.
  - *Mitigation:* Integrated sanitization pipeline [`labs/redact_evidence.py`](labs/redact_evidence.py:1) masks:
    - Authorization headers (`Bearer [REDACTED]`)
    - Passwords, secrets, tokens matching entropy or keyword patterns
    - Truncates raw HTTP response bodies to `MAX_BODY = 65536`.

### 4.5 Denial of Service (Scanner Availability & Resource Exhaustion)
- **Threat D1: Regular Expression Denial of Service (ReDoS)**
  - *Scenario:* Crafted source files exploit polynomial/exponential backtracking in static analyzer regular expressions.
  - *Risk:* High.
  - *Mitigation:* AST scanning avoids nested wildcards (`(a+)+`). Scans rely on discrete AST node visitor trees (`ast.Call`, `ast.Assign`) where possible rather than giant multi-line regexes.
- **Threat D2: HTTP Payload Memory Exhaustion**
  - *Scenario:* Juice Shop or target sends infinite chunked HTTP stream or multi-gigabyte payload.
  - *Risk:* Medium.
  - *Mitigation:* [`_request()`](labs/juice_shop_exploits.py:71) uses stream-limited reading capping payloads at 64 KB, with socket timeouts defaulting to 10 seconds.

### 4.6 Elevation of Privilege (Arbitrary Execution)
- **Threat E1: Remote Code Execution via Malicious Source Code**
  - *Scenario:* Scanned repository contains weaponized Python files that execute code upon parsing.
  - *Risk:* Critical.
  - *Mitigation:* Scanner uses strictly non-executing parser [`ast.parse()`](juicesec/astscan.py:100). No modules are imported dynamically, no pickling is used, and no shell execution (`os.system`, `subprocess.Popen`) is invoked on untrusted code snippets.

---

## 5. Threat Traceability Matrix

| Threat ID | STRIDE Category | Component Affected | Mitigation Implementation | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **S1** | Spoofing | `labs/juice_shop_exploits.py` | `validate_target()` host validation | [`test_core.py:test_validate_target`](tests/test_core.py:1) |
| **T1** | Tampering | `juicesec/astscan.py` | Read-only AST stream parser | [`test_core.py:test_ast_readonly`](tests/test_core.py:1) |
| **T2** | Tampering | `evaluate.py` | SHA-256 dataset pinning | [`test_core.py:test_checksum_verification`](tests/test_core.py:1) |
| **R1** | Repudiation | `juicesec/core.py` | Deterministic finding serialisation | [`test_core.py:test_report_generation`](tests/test_core.py:1) |
| **I1** | Info Disclosure | `labs/redact_evidence.py` | Automated pattern token mask | [`test_core.py:test_redaction`](tests/test_core.py:1) |
| **D1** | Denial of Service | `juicesec/astscan.py` | Linear regex & node matching | [`test_core.py:test_scan_performance`](tests/test_core.py:1) |
| **D2** | Denial of Service | `labs/juice_shop_exploits.py` | `MAX_BODY = 65536` body clamp | [`test_core.py:test_http_body_limit`](tests/test_core.py:1) |
| **E1** | Elevation of Priv | `juicesec/astscan.py` | Non-evaluating AST traversal | [`test_core.py:test_ast_no_exec`](tests/test_core.py:1) |
