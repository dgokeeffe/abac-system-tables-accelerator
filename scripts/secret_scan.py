#!/usr/bin/env python3
"""Small public-repository guard for concrete Databricks hosts and credentials."""

from __future__ import annotations

import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "build", "dist", "htmlcov", "__pycache__", ".mypy_cache"}
PATTERNS = (
    re.compile(r"https://(?:adb-|dbc-)[A-Za-z0-9.-]+"),
    re.compile(r"dapi[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


def main() -> int:
    findings: list[str] = []
    for path in sorted(Path(".").rglob("*")):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if any(pattern.search(line) for pattern in PATTERNS):
                findings.append(f"{path}:{line_number}: secret-shaped content")
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("secret scan clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
