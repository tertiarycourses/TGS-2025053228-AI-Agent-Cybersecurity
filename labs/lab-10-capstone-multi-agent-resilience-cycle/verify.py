#!/usr/bin/env python3
"""verify.py — deterministic acceptance check for Lab 10 (capstone).

Exercises capstone.py against the seeded evidence and asserts the known-correct
results, so a PASS proves the resilience improvement cycle is wired correctly:
  1. --ingest builds one dataset (falling back to sample-evidence when empty)
  2. --score covers ALL SIX domains with current [3,3,4,2,3,2] and
     target [4,4,4,4,4,3] (matches the deck chart)
  3. --backlog is sorted by gap DESC (Monitoring gap 2 first, then the gap-1
     items) and EVERY item is traceable to a source lab and to an LO
  4. --report carries a human-approval field on the proposed policy changes
     (the improver only proposes; a human must approve)
Exit code 0 = PASS, 1 = FAIL.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import capstone  # noqa: E402

EXPECTED_ORDER = ["Policy", "Access/Crypto", "Network", "Monitoring", "Response", "Recovery"]
EXPECTED_CURRENT = [3, 3, 4, 2, 3, 2]
EXPECTED_TARGET = [4, 4, 4, 4, 4, 3]

fails = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def main():
    print("Lab 10 — Capstone: Multi-Agent Cyber-Resilience Improvement Cycle · verifier\n")

    # 1) Ingest builds one dataset (evidence/ empty -> sample-evidence fallback).
    ds = capstone.ingest()
    check("ingest builds one dataset from the evidence", isinstance(ds, dict) and ds.get("record_count", 0) >= 9)
    check("  -> every record cites a source lab", all(r.get("source_lab") for r in ds["records"]))
    check("  -> every record cites a learning outcome", all(r.get("learning_outcome") for r in ds["records"]))

    # 2) Scorecard covers all six domains with the exact seeded profile.
    sc = capstone.score(ds)
    check("scorecard covers all six control domains", sc["domains_order"] == EXPECTED_ORDER)
    check("scorecard current profile == [3,3,4,2,3,2]", sc["current_profile"] == EXPECTED_CURRENT)
    check("scorecard target  profile == [4,4,4,4,4,3]", sc["target_profile"] == EXPECTED_TARGET)
    check("scorecard maturity values are on the 1-5 scale",
          all(1 <= d["current"] <= 5 and 1 <= d["target"] <= 5 for d in sc["domains"]))
    gaps = {d["domain"]: d["gap"] for d in sc["domains"]}
    check("scorecard gap: Monitoring == 2", gaps.get("Monitoring") == 2)
    check("scorecard gap: Recovery == 1", gaps.get("Recovery") == 1)
    check("scorecard gap: Network == 0 (already at target)", gaps.get("Network") == 0)

    # 3) Backlog sorted by gap DESC and fully traceable.
    bl = capstone.backlog(ds)
    items = bl["items"]
    check("backlog is non-empty", len(items) >= 1)
    bl_gaps = [it["gap"] for it in items]
    check("backlog is sorted by gap descending", bl_gaps == sorted(bl_gaps, reverse=True))
    check("backlog: the largest gap (Monitoring) sorts first",
          items[0]["domain"] == "Monitoring" and items[0]["gap"] == 2)
    check("backlog: within equal gaps, high risk precedes medium risk",
          _high_before_medium_within_gap(items))
    check("backlog: EVERY item is traceable to a source lab",
          all(it.get("source_labs") for it in items))
    check("backlog: EVERY item maps to an LO (LO1/LO2/LO3)",
          all(any(lo in ("LO1", "LO2", "LO3") for lo in it.get("maps_to_los", [])) for it in items))
    check("backlog: EVERY item carries a human-approval flag",
          all(it.get("requires_human_approval") is True for it in items))
    check("backlog: priorities are 1..n in order",
          [it["priority"] for it in items] == list(range(1, len(items) + 1)))

    # 4) Report: human-approval field present on the proposed changes.
    rep = capstone.build_report(ds)
    changes = rep.get("proposed_policy_changes", [])
    check("report proposes policy changes", len(changes) >= 1)
    check("report: a human-approval field is present on proposed changes",
          all(c.get("requires_human_approval") is True for c in changes))
    check("report: proposed changes are PENDING (not auto-applied)",
          all(c.get("approval_status") == "PENDING" for c in changes))
    ha = rep.get("human_approval", {})
    check("report: top-level human-approval gate is required and PENDING",
          ha.get("required") is True and ha.get("status") == "PENDING")
    check("report: proposed changes are traceable to source labs",
          all(c.get("source_labs") for c in changes))

    print()
    if fails:
        print("RESULT: FAIL (%d check(s) failed)" % len(fails))
        return 1
    print("RESULT: PASS — scorecard covers 6 domains [3,3,4,2,3,2]->[4,4,4,4,4,3], "
          "backlog is gap-sorted and lab-traceable, and proposed changes require human approval.")
    return 0


def _high_before_medium_within_gap(items):
    """No medium/low-risk item may precede a high-risk item of the SAME gap."""
    for i, a in enumerate(items):
        for b in items[i + 1:]:
            if a["gap"] == b["gap"]:
                if capstone.RISK_RANK.get(a["risk"], 0) < capstone.RISK_RANK.get(b["risk"], 0):
                    return False
    return True


if __name__ == "__main__":
    raise SystemExit(main())
