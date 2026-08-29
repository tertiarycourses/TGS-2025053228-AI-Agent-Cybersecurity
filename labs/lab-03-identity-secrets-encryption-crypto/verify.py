#!/usr/bin/env python3
"""verify.py — deterministic acceptance check for Lab 3.

Exercises the lab tooling against the seeded fixtures and asserts the known-correct
results, so a PASS proves the secret scanner, the hash-vs-encrypt classifier, the
password-entropy scorer and the certificate validator all work:

  1. secret_scan finds EXACTLY the 5 planted secrets (by file+line+kind)
  2. secret_scan NEVER emits a raw secret value (only redacted placeholders)
  3. --classify routes passwords/integrity -> HASH and secrets/PII/confidential -> ENCRYPT
  4. --entropy is STRICTLY INCREASING across the 4 tiers and flags the weak ones (<60 bits)
  5. the certificate is detected EXPIRED (notAfter < now)

Exit code 0 = PASS, 1 = FAIL.
"""
import datetime
import io
import os
import sys
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import secret_scan
import crypto_check

MD = os.path.join(HERE, "mock-data")
CONFIG = os.path.join(MD, "agent-config")
fails = []

# The exact planted secrets — (file, line, kind). Anything more or fewer is a FAIL.
EXPECTED_FINDINGS = {
    (".env.sample", 6, "Password in URL"),
    ("config.yaml", 11, "Cloud access key id"),
    ("config.yaml", 15, "Slack token"),
    ("settings.json", 10, "Generic API key"),
    ("settings.json", 15, "Private key block"),
}

# Raw secret substrings that must NEVER appear in the scanner's printed report.
RAW_SECRETS = [
    "AKIAJXQ7EXAMPLE9K2QZ",
    "xoxb-EXAMPLE-DO-NOT-USE",
    "sk-live-9f8e7d6c5b4a3d2e1f0aEXAMPLE0011223344",
    "S3cr3tP@ssw0rd_2024",
    "MIIEowIBAAKCAQEA0EXAMPLEFAKEKEYDONOTUSE",
]


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def main():
    print("Lab 3 — Identity, Secrets, Encryption & Crypto Validation · verifier\n")

    # 1) secret scan finds exactly the 5 planted secrets by file+line+kind
    findings = secret_scan.scan(CONFIG)
    got = {(f, ln, kind) for (f, ln, kind, _red) in findings}
    check("secret_scan finds exactly 5 planted secrets", len(findings) == 5)
    check("  -> secrets match the expected file+line+kind set", got == EXPECTED_FINDINGS)
    check("  -> secrets span 3 files (config.yaml, .env.sample, settings.json)",
          len({f for (f, _l, _k) in got}) == 3)
    check("  -> five distinct kinds detected (key id, token, api key, private key, password)",
          len({k for (_f, _l, k) in got}) == 5)

    # 2) the scanner never prints a raw secret value. Drive the real CLI (argv) and
    #    capture stdout, so this checks exactly what a learner would see on screen.
    report = _run_scanner_cli(CONFIG)
    leaked = [s for s in RAW_SECRETS if s in report]
    check("secret_scan report contains NO raw secret value", leaked == [])
    check("  -> report is redacted (contains the redaction marker)", "[redacted" in report)

    # 3) hash-vs-encrypt classification routes correctly
    import csv
    with open(os.path.join(MD, "data-items.csv"), newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    routed = {}
    for r in rows:
        typ = r["type"].strip().lower()
        routed[r["item"].strip()] = crypto_check.CLASSIFY_RULES.get(typ, ("ENCRYPT", ""))[0]
    check("--classify routes passwords -> HASH",
          routed["user_login_password"] == "HASH" and routed["admin_login_password"] == "HASH")
    check("--classify routes integrity data -> HASH",
          routed["file_download_checksum"] == "HASH" and routed["audit_log_digest"] == "HASH")
    check("--classify routes PII -> ENCRYPT",
          all(routed[i] == "ENCRYPT" for i in ("customer_email", "national_id_number", "home_address")))
    check("--classify routes secrets -> ENCRYPT",
          all(routed[i] == "ENCRYPT" for i in ("oauth_client_secret", "agent_api_key", "session_token")))
    check("--classify routes confidential data -> ENCRYPT", routed["credit_card_number"] == "ENCRYPT")

    # 4) password entropy strictly increases across the 4 tiers; weak ones flagged
    with open(os.path.join(MD, "creds-sample.txt"), encoding="utf-8") as f:
        pwds = [ln.rstrip("\n") for ln in f if ln.strip() != ""]
    bits = [crypto_check.entropy_bits(p) for p in pwds]
    check("--entropy reads exactly 4 password tiers", len(bits) == 4)
    check("--entropy is STRICTLY INCREASING across the 4 tiers",
          all(bits[i] < bits[i + 1] for i in range(len(bits) - 1)))
    check(f"  -> the two weakest are below the {crypto_check.ENTROPY_FLOOR_BITS}-bit floor",
          bits[0] < crypto_check.ENTROPY_FLOOR_BITS and bits[1] < crypto_check.ENTROPY_FLOOR_BITS)
    check(f"  -> the two strongest meet the {crypto_check.ENTROPY_FLOOR_BITS}-bit floor",
          bits[2] >= crypto_check.ENTROPY_FLOOR_BITS and bits[3] >= crypto_check.ENTROPY_FLOOR_BITS)

    # 5) certificate is detected EXPIRED
    now = datetime.datetime.now(datetime.timezone.utc)
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = crypto_check.cert(os.path.join(MD, "agent-cert.pem"), now=now)
    check("--cert detects the certificate as EXPIRED", result["expired"] is True)
    check("  -> cert exposes issuer, subject and key size",
          bool(result["subject"]) and bool(result["issuer"]) and result["key_bits"] == 2048)

    print()
    if fails:
        print(f"RESULT: FAIL ({len(fails)} check(s) failed)")
        return 1
    print("RESULT: PASS — all Lab 3 checks passed (5 secrets redacted, hash/encrypt routed, "
          "entropy increasing, cert EXPIRED).")
    return 0


def _run_scanner_cli(path):
    """Run secret_scan's real CLI on `path` and return everything it printed to stdout."""
    buf = io.StringIO()
    saved = sys.argv
    try:
        sys.argv = ["secret_scan.py", path]
        with redirect_stdout(buf):
            secret_scan.main()
    finally:
        sys.argv = saved
    return buf.getvalue()


if __name__ == "__main__":
    raise SystemExit(main())
