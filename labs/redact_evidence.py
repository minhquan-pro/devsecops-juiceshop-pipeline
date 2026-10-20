"""Redact tokens, cookies and JWTs from evidence files before publishing.

CI uploads the ``evidence/`` directory as a build artifact. Even on a throwaway
lab instance we do not want to publish usable credentials, so this pass rewrites
every JSON/text file in place with the sensitive substrings masked.

Usage::

    python labs/redact_evidence.py evidence/
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# A JWT is three base64url segments joined by dots.
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
# Bearer tokens in headers or text.
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
# Header lines for Authorization and Cookie.
HEADER_RE = re.compile(r"(?im)^((?:authorization|proxy-authorization|cookie|set-cookie):\s*).+$")
# Sensitive URL query parameters.
QUERY_PARAM_RE = re.compile(
    r"(?i)([?&](?:access_token|refresh_token|api_key|apikey|token|secret|password|client_secret)=)[^&\s\"'<>]+"
)

# Case-insensitive sensitive key pattern for JSON structures.
SENSITIVE_KEY_RE = re.compile(
    r"^(?:access[-_]?token|refresh[-_]?token|id[-_]?token|api[-_]?key|client[-_]?secret"
    r"|authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|bearer|token"
    r"|password|passwd|pwd|secret|apikey)$",
    re.IGNORECASE,
)
SENSITIVE_KEYS = {"token", "password", "authorization", "cookie", "secret", "apikey"}


def is_sensitive_key(key: str) -> bool:
    """Return True if dictionary key matches sensitive credential naming."""
    if not isinstance(key, str):
        return False
    norm = re.sub(r"[_\-]", "", key).lower()
    return bool(SENSITIVE_KEY_RE.match(key)) or norm in {
        "token", "accesstoken", "refreshtoken", "idtoken", "apikey",
        "clientsecret", "authorization", "proxyauthorization",
        "cookie", "setcookie", "bearer", "password", "secret",
    }


def redact_text(text: str) -> str:
    """Redact tokens, JWTs, headers, and query parameters from text content."""
    text = JWT_RE.sub("<jwt-redacted>", text)
    # JWT still base64 inside the middle segment of a preview: mask after 'eyJ'.
    text = re.sub(r"eyJ[A-Za-z0-9_-]+", "<jwt-redacted>", text)
    # Mask Bearer authentication tokens
    text = BEARER_RE.sub("Bearer <redacted>", text)
    # Mask HTTP header lines
    text = HEADER_RE.sub(r"\1<redacted>", text)
    # Mask sensitive URL query parameters
    text = QUERY_PARAM_RE.sub(r"\g<1><redacted>", text)
    return text


def redact_value(value):
    """Recursively mask sensitive values in structured data without mutating inputs."""
    if isinstance(value, dict):
        return {
            k: ("<redacted>" if is_sensitive_key(k) else redact_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python labs/redact_evidence.py <directory>", file=sys.stderr)
        return 2
    root = Path(argv[1])
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    touched = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in (".json", ".txt", ".html"):
            continue
        try:
            if path.suffix.lower() == ".json":
                data = json.loads(path.read_text(encoding="utf-8"))
                path.write_text(json.dumps(redact_value(data), ensure_ascii=False, indent=2),
                                encoding="utf-8")
            else:
                path.write_text(redact_text(path.read_text(encoding="utf-8")), encoding="utf-8")
            touched += 1
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
    print(f"redacted {touched} file(s) under {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
