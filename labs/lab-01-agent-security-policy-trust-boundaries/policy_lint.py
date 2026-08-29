#!/usr/bin/env python3
"""policy_lint.py — classify assets and lint an AI-agent security policy.

Standard library only. Two modes:
  --classify mock-data/asset-inventory.csv   print each asset's CIA classification
                                             and the controls it therefore requires
  --check    policy.yaml                      lint the policy; exit 1 if it violates
                                             the rules below, else exit 0

Lint rules (the machine-checkable core of Lab 1):
  R1  the policy must set a top-level prompt_contract (untrusted input is data)
  R2  every Confidential asset must have BOTH an 'access' and a 'crypto' control
  R3  every state-changing asset must set human_approval: required
  R4  every asset must declare a classification and at least one control
"""
import argparse, csv, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import miniyaml

REQUIRED_FOR_CONFIDENTIAL = {"access", "crypto"}


def load_policy(path):
    return miniyaml.load(path)


def lint(policy):
    """Return a list of violation strings ([] means the policy passes)."""
    v = []
    if not isinstance(policy, dict):
        return ["R0: policy is not a mapping / failed to parse"]
    if str(policy.get("prompt_contract", "")).strip() != "untrusted_input_is_data":
        v.append("R1: missing top-level prompt_contract: untrusted_input_is_data")
    for a in policy.get("assets", []) or []:
        name = a.get("name", "<unnamed>")
        cls = a.get("classification")
        controls = set(a.get("controls") or [])
        controls.discard("none")
        if not cls:
            v.append(f"R4: asset '{name}' has no classification")
        if not controls:
            v.append(f"R4: asset '{name}' declares no controls")
        if cls == "Confidential":
            missing = REQUIRED_FOR_CONFIDENTIAL - controls
            if missing:
                v.append(f"R2: Confidential asset '{name}' is missing control(s): {', '.join(sorted(missing))}")
        if a.get("state_changing") is True and str(a.get("human_approval", "")).strip() != "required":
            v.append(f"R3: state-changing asset '{name}' must set human_approval: required")
    return v


def classify(csv_path):
    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    print(f"{'ASSET':22} {'CLASSIFICATION':14} {'OWNER':12} REQUIRED CONTROLS")
    print("-" * 78)
    for r in rows:
        cls = r["classification"].strip()
        req = "access + crypto (+ approval if state-changing)" if cls == "Confidential" else (
              "access" if cls == "Internal" else "baseline / public")
        print(f"{r['asset'][:21]:22} {cls:14} {r['owner'][:11]:12} {req}")
    conf = sum(1 for r in rows if r["classification"].strip() == "Confidential")
    print("-" * 78)
    print(f"{len(rows)} assets · {conf} Confidential (need access + cryptography controls)")
    return rows


def main():
    ap = argparse.ArgumentParser(description="Classify assets and lint the agent security policy.")
    ap.add_argument("--classify", metavar="CSV", help="print the CIA classification for each asset")
    ap.add_argument("--check", metavar="POLICY", help="lint the policy file; exit 1 on any violation")
    args = ap.parse_args()
    if args.classify:
        classify(args.classify)
        return 0
    if args.check:
        pol = load_policy(args.check)
        violations = lint(pol)
        if violations:
            print(f"POLICY LINT: {len(violations)} violation(s) in {args.check}")
            for x in violations:
                print("  ✗ " + x)
            return 1
        n = len(pol.get("assets", []) or [])
        print(f"POLICY LINT: 0 violations — {n} assets, all Confidential assets have access + crypto,")
        print("             all state-changing rules require human approval, prompt contract set.")
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
