#!/usr/bin/env python3
"""harden_check.py — score a synthetic endpoint fleet against a hardening baseline.

Standard library only (csv). Two modes:

  --inventory mock-data/endpoints.csv
      Print the fleet inventory: one line per endpoint with its per-control
      pass/fail, plus the row count. Read-only; no network, no live host.

  --score baseline.yaml mock-data/endpoints.csv
      Read the required controls from the YAML baseline, compute the per-control
      PASS RATE across the fleet and the overall fleet posture, then list the
      WEAKEST controls so the learner can build a remediation plan. Emits the
      same numbers as posture.json for the evidence pack.

SAFETY: this tool only reads the synthetic inventory. It performs no scanning,
no exploitation and never contacts a real or internet host. Any live validation
in this lab is done ONLY against the authorized Ethical Hacking Trainer target
named in the README, using the read-only checks the README lists.
"""
import argparse, csv, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import miniyaml

# The five K2 endpoint-hardening controls, in report order.
CONTROLS = ["patching", "host_firewall", "disk_encryption", "mfa_rdp", "app_allowlist"]


def load_endpoints(csv_path):
    """Return the list of endpoint rows (dicts) from the inventory CSV."""
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def required_controls(baseline):
    """Return the ordered list of control ids marked required in the baseline."""
    out = []
    for c in baseline.get("controls", []) or []:
        if c.get("required") is True and c.get("id"):
            out.append(c["id"])
    return out


def pass_rates(rows, controls=CONTROLS):
    """Return {control: pass_rate_percent_int} across all endpoint rows."""
    n = len(rows) or 1
    rates = {}
    for c in controls:
        passed = sum(1 for r in rows if (r.get(c, "").strip().lower() == "pass"))
        # exact integer percentage (fleet is sized so these are whole numbers)
        rates[c] = round(passed * 100 / n)
    return rates


def score(baseline, rows):
    """Compute the full posture model from the baseline + inventory."""
    controls = required_controls(baseline)
    rates = pass_rates(rows, controls)
    # overall fleet posture = mean of the per-control pass rates
    overall = round(sum(rates[c] for c in controls) / (len(controls) or 1))
    # weakest controls = the two lowest pass rates (ascending), for remediation
    weakest = sorted(controls, key=lambda c: (rates[c], c))[:2]
    return {
        "endpoints": len(rows),
        "controls_required": controls,
        "pass_rate_pct": {c: rates[c] for c in controls},
        "fleet_posture_pct": overall,
        "weakest_controls": weakest,
    }


def print_inventory(rows):
    print(f"{'HOSTNAME':12} " + " ".join(f"{c:>15}" for c in CONTROLS))
    print("-" * (12 + 1 + 16 * len(CONTROLS)))
    for r in rows:
        cells = " ".join(f"{r.get(c, '').strip():>15}" for c in CONTROLS)
        print(f"{r.get('hostname', '<none>')[:12]:12} {cells}")
    print("-" * (12 + 1 + 16 * len(CONTROLS)))
    print(f"{len(rows)} endpoints in the synthetic inventory (read-only).")


def print_score(model):
    print("ENDPOINT HARDENING SCORE (synthetic fleet — no live host contacted)")
    print(f"  endpoints scored : {model['endpoints']}")
    print(f"  controls required: {', '.join(model['controls_required'])}")
    print()
    print(f"  {'CONTROL':16} PASS RATE")
    print("  " + "-" * 30)
    for c in model["controls_required"]:
        print(f"  {c:16} {model['pass_rate_pct'][c]:3d}%")
    print("  " + "-" * 30)
    print(f"  {'FLEET POSTURE':16} {model['fleet_posture_pct']:3d}%")
    print()
    print(f"  WEAKEST CONTROLS (remediate first): {', '.join(model['weakest_controls'])}")
    print("  Every 'apply hardening' change is PROPOSE-ONLY and needs HUMAN APPROVAL.")


def main():
    ap = argparse.ArgumentParser(description="Score endpoints against a hardening baseline.")
    ap.add_argument("--inventory", metavar="CSV", help="print the synthetic endpoint inventory")
    ap.add_argument("--score", nargs=2, metavar=("BASELINE", "CSV"),
                    help="score the CSV inventory against the YAML baseline")
    ap.add_argument("--json", action="store_true", help="with --score, also print posture.json")
    args = ap.parse_args()

    if args.inventory:
        print_inventory(load_endpoints(args.inventory))
        return 0
    if args.score:
        baseline = miniyaml.load(args.score[0])
        rows = load_endpoints(args.score[1])
        model = score(baseline, rows)
        print_score(model)
        if args.json:
            print()
            print(json.dumps(model, indent=2))
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
