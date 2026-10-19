# API Documentation

## Overview

JuiceSec provides both a **Web UI** and a **CLI interface** for security scanning. The Web UI runs on `http://127.0.0.1:5000` (localhost only for security).

---

## Web API Endpoints

### Session Management

#### `GET /api/session`

Get CSRF token for authenticated requests.

**Response:**
```json
{
  "csrf": "random_secure_token_here"
}
```

---

### Active Scanning

#### `POST /api/scan`

Scan a running Juice Shop instance.

**Headers:**
- `Content-Type: application/json`
- `X-CSRF-Token: <token_from_session>`
- `Origin: http://127.0.0.1:5000`

**Request Body:**
```json
{
  "target": "http://127.0.0.1:3000",
  "active": false
}
```

**Parameters:**
- `target` (string, required): URL of Juice Shop instance (must be localhost)
- `active` (boolean, optional): Whether to perform active probing (default: false)

**Response:**
```json
{
  "schema_version": "1.1",
  "mode": "http_scan",
  "target": "http://127.0.0.1:3000",
  "findings": [
    {
      "rule_id": "HDR-content-security-policy",
      "title": "Thiếu Content Security Policy",
      "severity": "low",
      "confidence": "high",
      "status": "needs_review",
      "cwe": "CWE-693",
      "evidence": "Không thấy header trên HTML gốc",
      "remediation": "Đánh giá chính sách theo ngữ cảnh"
    }
  ],
  "limits": ["HTTP scan only", "Indicators need manual verification"]
}
```

**Status Codes:**
- `200`: Scan completed successfully
- `403`: CSRF token or origin mismatch
- `409`: Another scan is in progress
- `413`: Request too large (> 250KB)
- `415`: Wrong content type

---

### Static Analysis

#### `POST /api/source`

Analyze source code (SAST).

**Headers:**
- `Content-Type: application/json`
- `X-CSRF-Token: <token_from_session>`
- `Origin: http://127.0.0.1:5000`

**Request Body:**
```json
{
  "source": "const user = req.query.id;\neval(user);",
  "filename": "vulnerable.js"
}
```

**Parameters:**
- `source` (string, required): Source code to analyze
- `filename` (string, optional): Filename for context (default: "snippet.txt")

**Response:**
```json
{
  "schema_version": "1.1",
  "mode": "sast_regex_ast_union",
  "target": "submitted source",
  "findings": [
    {
      "rule_id": "SAST-AST-EVAL",
      "title": "Dữ liệu không tin cậy chảy vào eval",
      "severity": "high",
      "confidence": "high",
      "line": 2,
      "evidence": "req.query.id → eval",
      "cwe": "CWE-95",
      "remediation": "Loại bỏ eval; dùng bộ phân tích có schema"
    }
  ]
}
```

---

### Report Retrieval

#### `GET /api/report`

Get last scan report (JSON).

**Response:**
```json
{
  "schema_version": "1.1",
  "findings": [...],
  "timestamp": "2026-10-19T06:20:00Z"
}
```

**Status Codes:**
- `200`: Report available
- `404`: No scan performed yet

---

#### `GET /api/report.html`

Get last scan report (HTML format).

**Response:** HTML document with styled findings table.

---

#### `GET /api/knowledge`

Get vulnerability knowledge base.

**Response:**
```json
{
  "rules": {
    "SAST-AST-XSS": {
      "title": "Cross-Site Scripting",
      "cwe": "CWE-79",
      "owasp": "A03:2021",
      "description": "...",
      "remediation": "..."
    }
  }
}
```

---

## CLI Interface

### Basic Commands

```bash
# Start Web UI
python app.py --port 5000

# Scan Juice Shop via CLI
python cli.py scan http://127.0.0.1:3000

# Analyze source file
python cli.py source vulnerable.js

# Run quality gate
python scan_gate.py --min-f1 0.55 --require-tests-pass

# Generate evaluation report
python evaluate.py
```

### CLI Options

#### `cli.py scan`
```bash
python cli.py scan <target_url> [--active] [--output report.json]
```

- `target_url`: Juice Shop URL (localhost only)
- `--active`: Enable active security probes
- `--output`: Save report to file

#### `cli.py source`
```bash
python cli.py source <file_path> [--output findings.json]
```

- `file_path`: Path to source file to analyze
- `--output`: Save findings to file

#### `scan_gate.py`
```bash
python scan_gate.py \
  --evidence evidence/validation.json \
  --min-f1 0.55 \
  --min-precision 0.55 \
  --min-recall 0.55 \
  --min-holdout-f1 0.55 \
  --max-p95-ms 500 \
  --require-tests-pass
```

**Exit Codes:**
- `0`: All quality thresholds met
- `1`: One or more thresholds failed (blocks CI/CD)

---

## Security Considerations

### Authentication & Authorization

- **Single-user design**: No multi-user support
- **Localhost only**: Bound to 127.0.0.1 (cannot be accessed remotely)
- **CSRF protection**: Required for all POST requests
- **Origin validation**: Strict same-origin policy

### Rate Limiting

- **Scan concurrency**: Maximum 1 concurrent scan
- **Request size**: Maximum 250KB payload
- **Timeout**: 5 seconds for request processing

### Content Security

- **CSP headers**: Strict policy preventing XSS
- **X-Frame-Options**: DENY (prevents clickjacking)
- **X-Content-Type-Options**: nosniff
- **Cache-Control**: no-store (prevents caching sensitive data)

---

## Error Responses

All errors follow this structure:

```json
{
  "error": "Human-readable error message"
}
```

**Common Error Codes:**

| Code | Meaning | Cause |
|------|---------|-------|
| 400 | Bad Request | Invalid JSON or parameters |
| 403 | Forbidden | CSRF/Origin check failed |
| 404 | Not Found | Resource not available |
| 409 | Conflict | Scan already in progress |
| 413 | Payload Too Large | Request > 250KB |
| 415 | Unsupported Media Type | Not application/json |

---

## Example Workflows

### 1. Web UI Scan

```javascript
// 1. Get CSRF token
const session = await fetch('/api/session').then(r => r.json());

// 2. Perform scan
const report = await fetch('/api/scan', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': session.csrf
  },
  body: JSON.stringify({
    target: 'http://127.0.0.1:3000',
    active: false
  })
}).then(r => r.json());

console.log(report.findings);
```

### 2. CLI Automated Scan

```bash
#!/bin/bash
# Automated CI/CD security scan

# Start Juice Shop
docker-compose up -d juice-shop

# Wait for service
sleep 10

# Run scan
python cli.py scan http://127.0.0.1:3000 --output scan-report.json

# Quality gate check
python scan_gate.py \
  --evidence evidence/validation.json \
  --min-f1 0.55 \
  --require-tests-pass

# Exit code 0 = pass, 1 = fail (blocks deployment)
```

### 3. Source Code Analysis

```bash
# Analyze single file
python cli.py source src/routes/payment.js --output findings.json

# Analyze directory (manual loop)
find src/ -name "*.js" -exec python cli.py source {} \;
```

---

## Performance Metrics

- **Scan latency**: P95 < 500ms (per endpoint)
- **Memory usage**: < 100MB (single scan)
- **Concurrent scans**: 1 (by design)
- **Max findings**: 200 per scan (truncated if exceeded)

---

## Schema Versions

### Current: 1.1

**Report Schema:**
```typescript
interface Report {
  schema_version: "1.1";
  mode: "http_scan" | "sast_regex_ast_union";
  target: string;
  findings: Finding[];
  limits: string[];
  timestamp?: string;
}

interface Finding {
  rule_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: "high" | "medium" | "low";
  status: "needs_review" | "confirmed" | "false_positive";
  cwe: string;
  evidence: string;
  remediation: string;
  line?: number;
}
```

---

## Support & Troubleshooting

### Common Issues

**1. "CSRF token rejected"**
- Ensure you call `/api/session` first
- Include `X-CSRF-Token` header in POST requests
- Set `Origin: http://127.0.0.1:<port>` header

**2. "A scan is already running"**
- Wait for current scan to complete
- Check server logs for stuck processes
- Restart server if needed

**3. "Only localhost is allowed"**
- Use `http://127.0.0.1:3000` not `http://localhost:3000`
- Cannot scan remote targets (by design)

### Debug Mode

```bash
# Enable verbose logging
PYTHONVERBOSE=1 python app.py

# Check service health
curl http://127.0.0.1:5000/api/session
```

---

## Related Documentation

- [`README.md`](../README.md): Project overview and setup
- [`ARCHITECTURE.md`](ARCHITECTURE.md): System design details
- [`CONTRIBUTING.md`](../CONTRIBUTING.md): Development guidelines
- [`SECURITY.md`](../SECURITY.md): Security policy
