#!/usr/bin/env python3
"""verify.py — deterministic acceptance check for Lab 1.

Exercises the lab tooling against the seeded fixtures and asserts the known-correct
results, so a PASS proves the policy linter and the trust-boundary derivation work:
  1. the mini-YAML loader round-trips a known structure
  2. the compliant policy.starter.yaml lints clean (0 violations)
  3. the seeded policy.broken.yaml is caught (missing crypto, missing approval, no contract)
  4. the trust boundary places every Confidential asset in the privileged zone
Exit code 0 = PASS, 1 = FAIL.
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import miniyaml, policy_lint, trust_boundary

MD = os.path.join(HERE, "mock-data")
fails = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def main():
    print("Lab 1 — Agent Security Policy & Trust Boundaries · verifier\n")

    # 1) mini-YAML loader
    doc = miniyaml.loads("a: 1\nb:\n  - x\n  - y\nc:\n  -\n    k: true\n    n: 3\n")
    check("mini-YAML parses scalars, sequences and block maps",
          doc == {"a": 1, "b": ["x", "y"], "c": [{"k": True, "n": 3}]})

    # 2) compliant starter policy lints clean
    starter = policy_lint.load_policy(os.path.join(MD, "policy.starter.yaml"))
    sv = policy_lint.lint(starter)
    check("policy.starter.yaml lints with 0 violations", sv == [])

    # 3) broken policy is caught with the seeded violations
    broken = policy_lint.load_policy(os.path.join(MD, "policy.broken.yaml"))
    bv = policy_lint.lint(broken)
    check("policy.broken.yaml is rejected", len(bv) >= 3)
    check("  → catches Confidential asset missing crypto (R2)", any("R2" in x and "crypto" in x for x in bv))
    check("  → catches state-changing rule missing approval (R3)", any("R3" in x for x in bv))
    check("  → catches missing prompt contract (R1)", any("R1" in x for x in bv))

    # 4) trust boundary places Confidential assets behind the gate
    tb = trust_boundary.build(starter)["trust_boundary"]
    priv = set(tb["privileged_zone"]["confidential_assets"])
    check("trust boundary: Confidential assets are in the privileged zone",
          {"learner_records", "admin_account", "agent_memory_store", "payment_tokens"} <= priv)
    check("trust boundary: scoped tools exclude 'none'", "none" not in tb["agent_core"]["scoped_tools"])
    check("trust boundary: read_records + read_memory are scoped tools",
          {"read_records", "read_memory"} <= set(tb["agent_core"]["scoped_tools"]))
    check("trust boundary: prompt contract is carried through",
          tb["agent_core"]["prompt_contract"] == "untrusted_input_is_data")

    print()
    if fails:
        print(f"RESULT: FAIL ({len(fails)} check(s) failed)")
        return 1
    print("RESULT: PASS — all Lab 1 checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
