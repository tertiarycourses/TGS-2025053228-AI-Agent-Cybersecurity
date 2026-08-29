#!/usr/bin/env python3
"""verify.py — deterministic acceptance check for Lab 6.

Exercises the lab tooling against the seeded fixtures and asserts the known-correct
results, so a PASS proves the hardening scorer works and the fleet matches the deck:
  1. the mini-YAML loader round-trips a known structure
  2. the baseline covers all 5 K2 controls (each required: true)
  3. the seeded endpoints.csv has EXACTLY 100 rows
  4. the computed per-control pass rates equal the deck chart
     (patching 72, host_firewall 65, disk_encryption 88, mfa_rdp 54, app_allowlist 41)
  5. the scorer flags mfa_rdp + app_allowlist as the weakest controls
Exit code 0 = PASS, 1 = FAIL.
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import miniyaml, harden_check

MD = os.path.join(HERE, "mock-data")
BASELINE = os.path.join(MD, "baseline.starter.yaml")
ENDPOINTS = os.path.join(MD, "endpoints.csv")

K2_CONTROLS = ["patching", "host_firewall", "disk_encryption", "mfa_rdp", "app_allowlist"]
EXPECTED_RATES = {"patching": 72, "host_firewall": 65, "disk_encryption": 88,
                  "mfa_rdp": 54, "app_allowlist": 41}

fails = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def main():
    print("Lab 6 — Endpoint Hardening & Controlled Validation · verifier\n")

    # 1) mini-YAML loader
    doc = miniyaml.loads("a: 1\nb:\n  - x\n  - y\nc:\n  -\n    k: true\n    n: 3\n")
    check("mini-YAML parses scalars, sequences and block maps",
          doc == {"a": 1, "b": ["x", "y"], "c": [{"k": True, "n": 3}]})

    # 2) baseline covers all 5 K2 controls, each required: true
    baseline = miniyaml.load(BASELINE)
    req = harden_check.required_controls(baseline)
    check("baseline covers all 5 K2 controls (each required: true)",
          sorted(req) == sorted(K2_CONTROLS))

    # 3) inventory has EXACTLY 100 endpoint rows
    rows = harden_check.load_endpoints(ENDPOINTS)
    check("endpoints.csv has exactly 100 rows", len(rows) == 100)

    # 4) per-control pass rates equal the deck chart
    rates = harden_check.pass_rates(rows, K2_CONTROLS)
    check("per-control pass rates equal [patching=72, host_firewall=65, "
          "disk_encryption=88, mfa_rdp=54, app_allowlist=41]",
          rates == EXPECTED_RATES)
    for c in K2_CONTROLS:
        check(f"  → {c} pass rate = {EXPECTED_RATES[c]}%", rates.get(c) == EXPECTED_RATES[c])

    # 5) the scorer flags the two weakest controls for the remediation plan
    model = harden_check.score(baseline, rows)
    check("scorer lists mfa_rdp + app_allowlist as the weakest controls",
          sorted(model["weakest_controls"]) == sorted(["mfa_rdp", "app_allowlist"]))

    print()
    if fails:
        print(f"RESULT: FAIL ({len(fails)} check(s) failed)")
        return 1
    print("RESULT: PASS — all Lab 6 checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
