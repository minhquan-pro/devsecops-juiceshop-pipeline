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
# Sensitive JSON keys whose values are always masked.
SENSITIVE_KEYS = {"token", "password", "authorization", "cookie", "secret", "apikey"}


def redact_text(text: str) -> str:
    text = JWT_RE.sub("<jwt-redacted>", text)
    # JWT still base64 inside the middle segment of a preview: mask after 'eyJ'.
    return re.sub(r"eyJ[A-Za-z0-9_-]+", "<jwt-redacted>", text)


def redact_value(value):
    if isinstance(value, dict):
        return {k: ("<redacted>" if k.lower() in SENSITIVE_KEYS else redact_value(v))
                for k, v in value.items()}
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
