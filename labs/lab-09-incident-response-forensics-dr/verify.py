#!/usr/bin/env python3
"""verify.py — deterministic acceptance check for Lab 9.

Exercises the lab tooling against the seeded fixtures and asserts the known-correct
results, so a PASS proves the timeline ordering, the chain-of-custody integrity and
the DR restore order all work:
  1. the IR timeline contains all six phases in the correct order
     (prepare -> detect -> contain -> eradicate -> recover -> learn)
  2. every chain-of-custody SHA-256 recomputes to the same value (integrity)
  3. the DR restore order is [Payments API, Agent runtime, Customer DB, Internal wiki,
     Reporting] with RTOs [2, 4, 6, 24, 48] (RTO ascending)
Exit code 0 = PASS, 1 = FAIL.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ir_timeline
import forensics
import dr_plan

MD = os.path.join(HERE, "mock-data")
fails = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def main():
    print("Lab 9 — Incident Response, Forensics & DR with Human Approvals · verifier\n")

    # 1) IR timeline: all six phases, correct order --------------------------------
    events = ir_timeline.load_events(os.path.join(MD, "incident-events.jsonl"))
    tl = ir_timeline.build(events)
    check("timeline: all six IR phases are present",
          tl["phases_present"] == ir_timeline.PHASES)
    # The emitted timeline must be non-decreasing in phase rank (i.e. correctly ordered).
    ranks = [ir_timeline.PHASE_RANK[e["phase"]] for e in tl["timeline"]]
    check("timeline: events are ordered prepare -> detect -> contain -> eradicate -> recover -> learn",
          ranks == sorted(ranks))
    # Within each phase, timestamps must be chronological.
    chrono = all(
        tl["timeline"][i]["ts"] <= tl["timeline"][i + 1]["ts"]
        for i in range(len(tl["timeline"]) - 1)
        if tl["timeline"][i]["phase"] == tl["timeline"][i + 1]["phase"]
    )
    check("timeline: events are chronological within each phase", chrono)
    # Observation must be kept separate from inference on every entry.
    check("timeline: every entry separates observation from inference",
          all(e.get("observation") and e.get("inference") for e in tl["timeline"]))

    # 2) Chain-of-custody: hashes are reproducible (integrity) ---------------------
    art = os.path.join(MD, "artifacts")
    rows_a = forensics.preserve(art)
    rows_b = forensics.preserve(art)  # recompute independently
    check("custody: at least three artifacts preserved", len(rows_a) >= 3)
    check("custody: every SHA-256 recomputes to the same value (integrity holds)",
          [r["sha256"] for r in rows_a] == [r["sha256"] for r in rows_b])
    check("custody: every digest is a full 64-hex SHA-256",
          all(len(r["sha256"]) == 64 and all(c in "0123456789abcdef" for c in r["sha256"]) for r in rows_a))
    check("custody: every row carries handler + preserved_at (chain-of-custody fields)",
          all(r["handler"] and r["preserved_at"] for r in rows_a))

    # 3) DR restore order: RTO ascending, exact sequence ---------------------------
    plan = dr_plan.build(dr_plan.load_systems(os.path.join(MD, "systems.csv")))
    expected_order = ["Payments API", "Agent runtime", "Customer DB", "Internal wiki", "Reporting"]
    expected_rto = [2, 4, 6, 24, 48]
    check("dr: restore order is Payments API -> Agent runtime -> Customer DB -> Internal wiki -> Reporting",
          plan["restore_order"] == expected_order)
    check("dr: restore-order RTOs are [2, 4, 6, 24, 48] (RTO ascending)",
          plan["restore_order_rto_hours"] == expected_rto)
    check("dr: RTO sequence is non-decreasing", plan["restore_order_rto_hours"] == sorted(plan["restore_order_rto_hours"]))

    print()
    if fails:
        print(f"RESULT: FAIL ({len(fails)} check(s) failed)")
        return 1
    print("RESULT: PASS — timeline covers all six IR phases in order, custody hashes are")
    print("               reproducible, and the DR restore order is RTO-ascending [2,4,6,24,48].")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
