#!/usr/bin/env python3
"""verify.py — deterministic acceptance check for Lab 4.

Exercises the lab tooling against the seeded fixtures and asserts the known-correct
results, so a PASS proves the subnet planner and the firewall validator work:
  1. right-sizing yields /27,/28,/29,/30 with usable host counts [30, 14, 6, 2]
     (the exact numbers the deck chart uses)
  2. --check accepts the good plan (subnets.solution.csv) with 0 problems
  3. --check flags the overlap seeded in subnets.bad.csv
  4. fw_validate flags the seeded tool_sandbox -> sensitive_data ALLOW violation
  5. fw_validate passes a clean rule set (the policy's own allowed_flows)
Exit code 0 = PASS, 1 = FAIL.
"""
import ipaddress, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import miniyaml, subnet_plan, fw_validate

MD = os.path.join(HERE, "mock-data")
fails = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def main():
    print("Lab 4 — Network Segmentation & IP Policy · verifier\n")

    # 1) right-sizing yields the exact deck numbers [30, 14, 6, 2] for /27,/28,/29,/30
    reqs = subnet_plan.read_requirements(os.path.join(MD, "zone-requirements.csv"))
    rows = subnet_plan.plan(reqs)
    prefixes = [int(r["cidr"].split("/")[1]) for r in rows]
    usable = [r["usable"] for r in rows]
    check("plan uses prefixes /27,/28,/29,/30", prefixes == [27, 28, 29, 30])
    check("plan usable-host counts are [30, 14, 6, 2]", usable == [30, 14, 6, 2])
    check("  → /27 gives 30 usable", subnet_plan.usable_hosts(ipaddress.ip_network("10.20.0.0/27")) == 30)
    check("  → /28 gives 14 usable", subnet_plan.usable_hosts(ipaddress.ip_network("10.20.0.32/28")) == 14)
    check("  → /29 gives 6 usable", subnet_plan.usable_hosts(ipaddress.ip_network("10.20.0.48/29")) == 6)
    check("  → /30 gives 2 usable", subnet_plan.usable_hosts(ipaddress.ip_network("10.20.0.56/30")) == 2)
    check("proposed plan has no internal overlaps",
          subnet_plan._find_overlaps([r["_net"] for r in rows]) == [])

    # 2) the good plan validates clean
    good = subnet_plan.check(os.path.join(MD, "subnets.solution.csv"))
    check("subnets.solution.csv validates with 0 problems", good == [])

    # 3) the seeded overlap is caught
    bad = subnet_plan.check(os.path.join(MD, "subnets.bad.csv"))
    check("subnets.bad.csv is rejected", len(bad) >= 1)
    check("  → overlap is detected", any("OVERLAP" in x for x in bad))

    # 4) fw_validate flags the seeded tool_sandbox -> sensitive_data ALLOW
    policy = fw_validate.load_policy(os.path.join(HERE, "segmentation-policy.yaml"))
    rules = fw_validate.read_rules(os.path.join(HERE, "firewall-rules.csv"))
    _, flagged = fw_validate.validate(policy, rules)
    seeded = [f for f in flagged if f["src"] == "tool_sandbox" and f["dst"] == "sensitive_data" and f["action"] == "ALLOW"]
    check("fw_validate flags the seeded tool_sandbox->sensitive_data ALLOW", len(seeded) == 1)
    check("  → exactly one rule is flagged in the seeded set", len(flagged) == 1)

    # 5) a clean rule set (the policy's own allowed_flows) passes
    clean_rules = [
        {"src_zone": f["src"], "dst_zone": f["dst"], "port": f["port"], "action": "ALLOW"}
        for f in policy.get("allowed_flows", [])
    ]
    _, clean_flagged = fw_validate.validate(policy, clean_rules)
    check("fw_validate passes a clean rule set (0 flagged)", clean_flagged == [])

    print()
    if fails:
        print(f"RESULT: FAIL ({len(fails)} check(s) failed)")
        return 1
    print("RESULT: PASS — all Lab 4 checks passed (right-sizing [30,14,6,2], overlap caught, seeded violation flagged).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
