#!/usr/bin/env python3
"""verify.py — deterministic acceptance check for Lab 2.

Exercises the extractor against the seeded phishing fixtures and asserts the
known-correct results, so a PASS proves the regex catalogue and ioc_extract.py
work end to end:
  1. patterns.txt loads and compiles (url, ipv4, sha256, sender)
  2. the by-type counts equal the seeded chart: url=14, ipv4=6, sha256=4,
     sender=5, attachment=3 (and the total is 32)
  3. every SEEDED indicator is found (exact expected value set, per type)
  4. NO phantom indicator is reported (found set == expected set, no extras)
  5. every IOC carries a source file + a positive line number
  6. --score adds a confidence in [0,1] and splits observation (literal string)
     from inference (why suspicious) for every IOC
Exit code 0 = PASS, 1 = FAIL.
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ioc_extract

PHISH = os.path.join(HERE, "mock-data", "phish")
PATTERNS = os.path.join(HERE, "patterns.txt")

EXPECTED_COUNTS = {"url": 14, "ipv4": 6, "sha256": 4, "sender": 5, "attachment": 3}

# The complete set of SEEDED indicators (value only) that MUST appear — used both to
# prove every seed is found and to prove nothing extra (phantom) is reported.
EXPECTED = {
    "url": {
        "https://secure-login-example.tld/reset?token=8842",
        "http://secure-login-example.tld/verify/session-8842",
        "http://portal.secure-login-example.tld/sso",
        "https://evil-example.test/pay/INV-20826",
        "http://evil-example.test/invoice/INV-20826.pdf",
        "https://billing.evil-example.test/dispute",
        "https://account-verify-example.tld/activity/3310",
        "http://account-verify-example.tld/confirm?u=3310",
        "https://mfa.account-verify-example.tld/enroll",
        "https://payroll-example.test/bank/update",
        "http://payroll-example.test/deposit/enroll",
        "https://payslips.payroll-example.test/archive",
        "https://delivery-notice-example.tld/reschedule/6677",
        "http://delivery-notice-example.tld/fee?ref=6677",
    },
    "ipv4": {
        "198.51.100.23", "203.0.113.44", "198.51.100.77",
        "203.0.113.91", "198.51.100.150", "203.0.113.20",
    },
    "sha256": {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5",
        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7",
    },
    "sender": {
        "secure-login-example.tld", "evil-example.test", "account-verify-example.tld",
        "payroll-example.test", "delivery-notice-example.tld",
    },
    "attachment": {
        "Account-Recovery-Form.pdf", "Invoice-INV-20826.pdf.exe", "Bank-Authorisation.xlsm",
    },
}

fails = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def main():
    print("Lab 2 — Phishing & IOC Triage with Regex Generation · verifier\n")

    # 1) patterns.txt loads and compiles the four catalogue types
    patterns = ioc_extract.load_patterns(PATTERNS)
    types = {t for t, _ in patterns}
    check("patterns.txt compiles the four catalogue types (url, ipv4, sha256, sender)",
          {"url", "ipv4", "sha256", "sender"} <= types)

    # Build the report once from the seeded fixtures.
    report = ioc_extract.build_report(PHISH, patterns)
    iocs = report["iocs"]
    by_type = {t: [i for i in iocs if i["type"] == t] for t in EXPECTED_COUNTS}

    # 2) by-type counts equal the seeded chart
    check("by-type counts equal [url=14, ipv4=6, sha256=4, sender=5, attachment=3]",
          report["counts_by_type"] == EXPECTED_COUNTS)
    check("total indicators == 32", report["total"] == 32)

    # 3) every seeded indicator is found  &  4) no phantom indicator is reported
    for t in ("url", "ipv4", "sha256", "sender", "attachment"):
        found = {i["value"] for i in by_type[t]}
        missing = EXPECTED[t] - found
        extra = found - EXPECTED[t]
        check(f"  → every seeded {t} is found ({len(EXPECTED[t])})", not missing)
        check(f"  → no phantom {t} reported", not extra)

    # 5) every IOC carries a source file + a positive line number
    check("every IOC has a source file",
          all(i.get("file") for i in iocs))
    check("every IOC has a positive source line number",
          all(isinstance(i.get("line"), int) and i["line"] > 0 for i in iocs))

    # 6) --score adds confidence in [0,1] and splits observation from inference
    scored = ioc_extract.score_report(ioc_extract.build_report(PHISH, patterns))["iocs"]
    check("--score gives every IOC a confidence in [0,1]",
          all(isinstance(i.get("confidence"), (int, float)) and 0.0 <= i["confidence"] <= 1.0
              for i in scored))
    check("--score keeps OBSERVATION == the literal string",
          all(i.get("observation") == i.get("value") for i in scored))
    check("--score adds a non-empty INFERENCE (why suspicious) per IOC",
          all(isinstance(i.get("inference"), str) and i["inference"] for i in scored))
    check("--score flags the double-extension attachment highest",
          max(scored, key=lambda i: i["confidence"])["value"].lower().endswith(".pdf.exe"))

    print()
    if fails:
        print(f"RESULT: FAIL ({len(fails)} check(s) failed)")
        return 1
    print("RESULT: PASS — all Lab 2 checks passed "
          "(14 URLs, 6 IPs, 4 hashes, 5 senders, 3 attachments; every IOC cited; no phantoms).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
