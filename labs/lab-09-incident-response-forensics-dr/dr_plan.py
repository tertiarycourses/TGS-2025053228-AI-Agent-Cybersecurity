#!/usr/bin/env python3
"""dr_plan.py — build a disaster-recovery plan from a systems inventory.

Standard library only (csv, json). Reads a systems CSV (system, rto_hours,
rpo_minutes, criticality) and emits a recovery plan as JSON to stdout:

  python3 dr_plan.py --systems mock-data/systems.csv > evidence/recovery-plan.json

Two things are derived per the deck:
  * BACKUP FREQUENCY from the RPO — backups must run at least as often as the RPO
    window (you can only lose up to one backup interval of data), so the recommended
    interval equals the RPO in minutes.
  * RESTORE ORDER sorted by RTO ascending — the system with the tightest recovery
    objective (smallest RTO) is restored first.
"""
import argparse
import csv
import json
import sys


def _rpo_to_frequency(rpo_minutes):
    """Human-readable backup cadence: back up at least once per RPO window."""
    m = int(rpo_minutes)
    if m % 1440 == 0:
        every = f"{m // 1440} day(s)"
    elif m % 60 == 0:
        every = f"{m // 60} hour(s)"
    else:
        every = f"{m} minute(s)"
    return {"interval_minutes": m, "description": f"back up every {every}"}


def load_systems(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def build(rows):
    systems = []
    for r in rows:
        systems.append({
            "system": r["system"].strip(),
            "rto_hours": int(r["rto_hours"]),
            "rpo_minutes": int(r["rpo_minutes"]),
            "criticality": r["criticality"].strip(),
            "backup_frequency": _rpo_to_frequency(r["rpo_minutes"]),
        })
    # Restore order: smallest RTO first (tightest recovery objective recovers first).
    # Tie-break on the original CSV order for stable, deterministic output.
    order = sorted(systems, key=lambda s: (s["rto_hours"],))
    restore_order = [s["system"] for s in order]
    rto_sequence = [s["rto_hours"] for s in order]
    return {
        "plan": "agent-incident-disaster-recovery",
        "systems": systems,
        "restore_order": restore_order,
        "restore_order_rto_hours": rto_sequence,
        "notes": "Restore order is RTO ascending; each system is backed up at least once per RPO window.",
    }


def main():
    ap = argparse.ArgumentParser(description="Build a DR plan (restore order + backup frequency) from a systems CSV.")
    ap.add_argument("--systems", required=True, metavar="CSV", help="systems inventory CSV")
    args = ap.parse_args()
    model = build(load_systems(args.systems))
    json.dump(model, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
