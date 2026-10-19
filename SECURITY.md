# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Architecture

This project implements multiple layers of defense:

### 1. Container Security
- ✅ **Non-root execution**: All containers run as unprivileged user (UID 10001)
- ✅ **Read-only filesystem**: Root filesystem mounted read-only
- ✅ **Dropped capabilities**: All Linux capabilities dropped, minimal added back
- ✅ **Resource limits**: CPU and memory limits enforced
- ✅ **No new privileges**: `no-new-privileges` security option enabled

### 2. Application Security
- ✅ **Zero dependencies**: No third-party runtime dependencies = minimal attack surface
- ✅ **Localhost-only**: HTTP collection restricted to loopback (127.0.0.1/::1)
- ✅ **CSRF protection**: Cryptographically secure tokens for state-changing operations
- ✅ **Security headers**: CSP, X-Frame-Options, X-Content-Type-Options enforced
- ✅ **Input validation**: Strict allowlisting for URLs, paths, and payloads
- ✅ **Credential redaction**: Automatic redaction of Set-Cookie, Authorization headers

### 3. Development Security
- ✅ **Pre-commit hooks**: Gitleaks, Bandit, secret detection
- ✅ **CI/CD scanning**: Trivy (container), Bandit (SAST), TruffleHog (secrets)
- ✅ **Quality gates**: Automated fail-closed gates for security regressions

## Reporting a Vulnerability

**DO NOT** open a public issue for security vulnerabilities.

Instead, email security reports to: [your-email@domain.com]

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

### Response Timeline
- **Initial response**: Within 48 hours
- **Status update**: Within 7 days
- **Fix timeline**: Critical (48h), High (7d), Medium (30d)

## Security Testing

Run security validation:

```bash
# SAST scan
bandit -r juicesec/ -ll

# Container image scan
docker build -t juicesec:test .
trivy image --severity HIGH,CRITICAL juicesec:test

# Secret detection
gitleaks detect --source . --verbose

# Run quality gate
python evaluate.py
python scan_gate.py --min-f1 0.95 --require-tests-pass
```

## Known Limitations

This is an **educational security scanner**, not a production security tool:
- ❌ No exploit confirmation (findings are indicators, not proven vulnerabilities)
- ❌ No authentication or multi-user support
- ❌ No persistent storage or database
- ❌ Localhost-only operation (by design)

## Secure Configuration

### Docker Compose Production Settings

```yaml
services:
  juicesec:
    image: juicesec:latest
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits: {cpus: '1', memory: 512M}
```

### Environment Variables

Never commit these to Git:
- API keys
- Tokens
- Passwords
- Private keys
- Connection strings

Use environment variable injection or secret management tools (HashiCorp Vault, AWS Secrets Manager).

## Compliance

This project follows:
- ✅ OWASP DevSecOps Guidelines
- ✅ CIS Docker Benchmark v1.6.0
- ✅ NIST SP 800-190 (Container Security)
- ✅ Python Security Best Practices (OWASP)

## License

Security reports and fixes are covered under the same license as the project.
