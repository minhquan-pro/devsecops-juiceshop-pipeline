# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-10-19

### Added
- Docker Compose hardening with resource limits, read-only filesystem, and capability dropping
- CI/CD security scanning pipeline (Trivy, Bandit, TruffleHog)
- Pre-commit hooks for secret detection and SAST
- SECURITY.md with comprehensive security policy
- Healthcheck configuration for containers
- CHANGELOG.md for version tracking

### Security
- **CRITICAL**: Enforced container resource limits to prevent DoS via resource exhaustion
- **HIGH**: Added tmpfs mount with noexec for temporary files
- **HIGH**: Dropped all Linux capabilities and added only NET_BIND_SERVICE
- **HIGH**: Enabled no-new-privileges security option
- **MEDIUM**: Added automated secret scanning in CI/CD pipeline
- **MEDIUM**: Implemented pre-commit hooks to prevent credential leaks

### Changed
- Updated Docker Compose to v2 syntax with deploy resources
- Enhanced security headers in application responses
- Improved error handling to fail-closed on exceptions

### Fixed
- Container now properly runs as non-root user (juicesec:10001)
- Memory leak prevention through strict resource limits

## [1.0.0] - 2024-XX-XX

### Added
- Initial release of JuiceSec educational security scanner
- Zero-dependency Python security analyzer
- AST-based static analysis for Python and JavaScript
- HTTP response analyzer with security checks
- Web UI for interactive scanning
- CLI for batch operations
- Docker containerization
- Comprehensive test suite with 95%+ coverage

### Security
- Localhost-only operation by design
- CSRF protection with secure tokens
- Credential redaction in evidence
- Security headers (CSP, X-Frame-Options)

---

## Security Update Policy

- **Critical**: Patches released within 48 hours
- **High**: Patches released within 7 days
- **Medium**: Patches released within 30 days
- **Low**: Addressed in next minor release

## Upgrade Guide

### From 1.0.x to 1.1.x

1. Update docker-compose.yml with new security settings:
```bash
docker-compose down
docker-compose up -d
```

2. Install pre-commit hooks:
```bash
pip install pre-commit
pre-commit install
```

3. Run security validation:
```bash
python evaluate.py
python scan_gate.py --require-tests-pass
```

No breaking changes in API or functionality.
