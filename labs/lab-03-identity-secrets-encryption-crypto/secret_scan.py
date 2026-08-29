#!/usr/bin/env python3
"""secret_scan.py — recursively scan agent config for hard-coded secrets.

Standard library only. Walks a directory, reads every text file, and flags lines
that look like a hard-coded secret (API keys, tokens, passwords, private keys)
using a small set of regex detectors.

  python3 secret_scan.py mock-data/agent-config/

For every hit it prints the FILE, the LINE NUMBER and the KIND of secret — but it
NEVER prints the secret value. The match is redacted to its first two characters
plus a length-preserving mask (e.g. 'AK****************' -> 'AK…[18 chars]'), so an
assessor can see a leak was found without the report itself becoming a leak.
"""
import argparse
import os
import re
import sys

# Each detector: (kind, compiled regex). Group 1 (if present) is the secret value to
# redact; otherwise the whole match is redacted. Patterns are intentionally narrow so
# the report is deterministic on the seeded fixtures.
DETECTORS = [
    ("Cloud access key id", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("Slack token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})")),
    ("Generic API key", re.compile(r"\b(sk-[A-Za-z0-9-]{16,})\b")),
    ("Private key block", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)")),
    ("Password assignment", re.compile(
        r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{6,})")),
    ("Password in URL", re.compile(r"://[^:/\s]+:([^@/\s]{4,})@")),
]

# Files we never treat as secret-bearing text (binary / noise).
SKIP_EXT = {".pyc", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz"}


def redact(value):
    """Return a non-reversible placeholder that reveals length but not content."""
    value = value.strip()
    if len(value) <= 2:
        return "…[redacted]"
    return value[:2] + "…[redacted, " + str(len(value)) + " chars]"


def scan_line(line):
    """Yield (kind, redacted) for every detector that fires on this line."""
    for kind, rx in DETECTORS:
        m = rx.search(line)
        if m:
            secret = m.group(1) if m.groups() else m.group(0)
            yield kind, redact(secret)


def iter_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _dirs, names in os.walk(root):
        for n in sorted(names):
            if os.path.splitext(n)[1].lower() in SKIP_EXT:
                continue
            yield os.path.join(dirpath, n)


def scan(root):
    """Return a sorted list of findings: (relpath, lineno, kind, redacted)."""
    findings = []
    base = root if os.path.isdir(root) else os.path.dirname(root) or "."
    for path in iter_files(root):
        try:
            with open(path, "r", encoding="utf-8", errors="strict") as f:
                lines = f.readlines()
        except (UnicodeDecodeError, OSError):
            continue  # skip binaries / unreadable files
        rel = os.path.relpath(path, base)
        for i, line in enumerate(lines, start=1):
            for kind, red in scan_line(line):
                findings.append((rel, i, kind, red))
    findings.sort(key=lambda t: (t[0], t[1], t[2]))
    return findings


def main():
    ap = argparse.ArgumentParser(description="Recursively scan for hard-coded secrets (values are redacted).")
    ap.add_argument("path", help="directory (or file) to scan, e.g. mock-data/agent-config/")
    args = ap.parse_args()
    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    findings = scan(args.path)
    print(f"SECRET SCAN: {args.path}")
    print("-" * 72)
    if not findings:
        print("No hard-coded secrets found.")
        print("-" * 72)
        print("0 finding(s).")
        return 0
    print(f"{'FILE':22} {'LINE':>4}  {'KIND':22} VALUE (redacted)")
    for rel, lineno, kind, red in findings:
        print(f"{rel[:21]:22} {lineno:>4}  {kind[:21]:22} {red}")
    print("-" * 72)
    print(f"{len(findings)} finding(s). Values are redacted — rotate each secret and move it to a vault.")
    # Non-zero exit so this can gate CI: leaked secrets are a failure.
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
