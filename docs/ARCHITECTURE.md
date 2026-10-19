# Kiến Trúc Hệ Thống JuiceSec Pipeline

## Tổng Quan

```
┌─────────────────────────────────────────────────────────────┐
│                    DevSecOps Pipeline                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐      ┌──────────────┐                     │
│  │   CLI Mode   │      │   Web UI     │                     │
│  │   (cli.py)   │      │   (app.py)   │                     │
│  └──────┬───────┘      └──────┬───────┘                     │
│         │                     │                              │
│         └──────────┬──────────┘                              │
│                    ▼                                         │
│         ┌─────────────────────┐                              │
│         │   Core Scanner      │                              │
│         │  (juicesec/core.py) │                              │
│         └──────────┬──────────┘                              │
│                    │                                         │
│         ┌──────────┴──────────┐                              │
│         ▼                     ▼                              │
│  ┌─────────────┐      ┌─────────────┐                       │
│  │ HTTP Scan   │      │  AST Scan   │                       │
│  │  (Dynamic)  │      │  (Static)   │                       │
│  └─────────────┘      └─────────────┘                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
         │                                │
         ▼                                ▼
┌─────────────────┐            ┌─────────────────┐
│  scan_gate.py   │            │  evaluate.py    │
│  (Quality Gate) │            │  (Metrics)      │
└─────────────────┘            └─────────────────┘
         │                                │
         ▼                                ▼
    Exit Code 0/1                   Evidence JSON
```

## Các Thành Phần Chính

### 1. Core Scanner (`juicesec/core.py`)
- **Chức năng:** Quét HTTP responses và phân tích lỗ hổng bảo mật
- **Input:** Target URL (chỉ localhost)
- **Output:** Structured findings (JSON)
- **Bảo mật:** 
  - Chỉ cho phép loopback (127.0.0.1, localhost, ::1)
  - Redact credentials trong headers
  - Giới hạn body size (262KB)

### 2. AST Scanner (`juicesec/astscan.py`)
- **Chức năng:** Static analysis với Python AST và token-based JS analysis
- **Taint Tracking:** Theo dõi data flow từ source → sink
- **Coverage:**
  - SQL Injection (CWE-89)
  - XSS (CWE-79)
  - Command Injection (CWE-78)
  - Path Traversal (CWE-22)
  - SSRF (CWE-918)
  - Insecure Deserialization (CWE-502)

### 3. Quality Gate (`scan_gate.py`)
- **Chức năng:** CI/CD gate kiểm tra regression
- **Logic:** **FAIL-CLOSED** - Exit 1 khi có lỗi
- **Thresholds:**
  - `--min-f1`: F1 score tối thiểu
  - `--min-recall`: Recall tối thiểu
  - `--max-p95-ms`: P95 latency tối đa

### 4. Web UI (`app.py`)
- **Framework:** Python stdlib HTTP server (zero dependencies)
- **Bảo mật:**
  - CSRF token per-session
  - Host header validation
  - CSP headers strict
  - X-Frame-Options: DENY
  - Origin checking
- **Endpoints:**
  - `GET /api/session` - CSRF token
  - `POST /api/scan` - Scan target
  - `POST /api/source` - Analyze code snippet
  - `GET /api/report` - Lấy kết quả

## Luồng Dữ Liệu

### Active Scan Mode
```
User → CLI/Web → core.scan()
                    ↓
            HTTP requests to target
                    ↓
            Response analysis
                    ↓
            Findings extraction
                    ↓
            JSON Report
```

### Static Analysis Mode
```
User → Submit code → astscan.analyze_*()
                           ↓
                    Parse AST/Tokens
                           ↓
                    Taint tracking
                           ↓
                    Match sinks
                           ↓
                    Findings
```

## Nguyên Tắc Thiết Kế

### 1. Zero Dependencies
- Chỉ dùng Python stdlib
- Không cài third-party packages
- Build image < 100MB

### 2. Localhost Only
- Không quét external targets
- Ngăn chặn SSRF accidental
- Phù hợp lab/educational use

### 3. Conservative Analysis
- High confidence findings only
- Status: `needs_review` mặc định
- Không exploit tự động

### 4. Evidence-Based
- Lưu SHA-256 của responses
- Reproducible scans
- Audit trail đầy đủ

## Deployment Patterns

### Development
```bash
python app.py --port 5000
```

### CI/CD
```bash
python evaluate.py > evidence/validation.json
python scan_gate.py --min-f1 0.9 --require-tests-pass
```

### Container
```bash
docker compose up
docker exec -it juicesec python cli.py scan http://juice-shop:3000
```

## Security Model

### Threat Model
- **IN SCOPE:** Phát hiện lỗ hổng trong target application
- **OUT OF SCOPE:** Exploitation, credential stuffing, brute-force

### Trust Boundaries
```
┌─────────────────────┐
│  Untrusted Input    │ ← Target responses, user code
└──────────┬──────────┘
           │ Validation
           ▼
┌─────────────────────┐
│  Scanner Logic      │ ← Trusted code
└──────────┬──────────┘
           │ Sanitization
           ▼
┌─────────────────────┐
│  Evidence Output    │ ← Redacted, safe for sharing
└─────────────────────┘
```

### Defense Layers
1. **Input Validation:** URL parsing, host checking
2. **Size Limits:** Body, source code, request count
3. **Timeouts:** HTTP requests, processing
4. **Redaction:** Credentials, PII trong logs
5. **Isolation:** Container non-root, read-only FS

## Performance Characteristics

### Scan Times (P95)
- HTTP collection: ~500ms
- AST analysis: ~100ms per file
- Full pipeline: <2s for typical app

### Resource Usage
- Memory: ~50MB baseline
- CPU: Burst during AST parsing
- Disk: Evidence files ~1MB per scan

## Extension Points

### Adding New Rules
```python
# In juicesec/core.py
def analyze_response(record):
    # Add custom finding
    if condition:
        out.append(finding(
            "CUSTOM-001",
            "Title",
            "severity",
            "confidence",
            "Evidence text",
            "Remediation steps",
            "CWE-XXX"
        ))
```

### Custom AST Patterns
```python
# In juicesec/astscan.py
SINK_RULES["newsink"] = (
    "SAST-AST-NEW",
    "Description",
    "CWE-XXX",
    "Remediation"
)
```

## Versioning & Compatibility

- **Schema Version:** 1.1 (documented in code)
- **Python:** 3.10+ required (tested on 3.12)
- **Breaking Changes:** Documented in CHANGELOG.md

## References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)
- [Python AST Documentation](https://docs.python.org/3/library/ast.html)
