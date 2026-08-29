#!/usr/bin/env python3
"""capstone.py — Multi-Agent Cyber-Resilience Improvement Cycle (Lab 10).

Standard library only (json, csv, argparse, os, sys). No third-party deps.

This capstone rolls up the evidence produced across Labs 1-9 into one resilience
improvement cycle run by a four-agent team (monitor -> triage -> responder ->
improver). It is deliberately deterministic so the seeded scorecard matches the
deck chart exactly.

Commands (the exact ones the lab asks for):
  python3 capstone.py --ingest evidence/          build one dataset from the evidence
  python3 capstone.py --score  > evidence/scorecard.json   resilience maturity scorecard
  python3 capstone.py --backlog > evidence/backlog.json    prioritised improvement backlog
  python3 capstone.py --report                    board-ready summary (+ human-approval gate)

Pipeline mapping (agent -> job):
  monitor    reads the raw evidence     (--ingest)
  triage     scores maturity per domain (--score)
  responder  builds the ranked backlog  (--backlog)
  improver   drafts the board report and PROPOSES policy changes that a HUMAN
             must APPROVE before the report is finalised (--report). Propose-only.

Aggregation rule (documented so a learner can reproduce it by hand):
  * CURRENT for a domain = the MINIMUM current maturity of its source labs
    ("resilience is only as strong as the weakest evidence in the domain").
  * TARGET  for a domain = the MAXIMUM target maturity of its source labs.
  This reproduces the deck chart:
    domains  [Policy, Access/Crypto, Network, Monitoring, Response, Recovery]
    current  [3,      3,            4,       2,          3,        2]
    target   [4,      4,            4,       4,          4,        3]
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_DIR = os.path.join(HERE, "evidence")
SAMPLE_DIR = os.path.join(HERE, "mock-data", "sample-evidence")

# Fixed presentation order for the six control domains (matches the deck chart).
DOMAIN_ORDER = ["Policy", "Access/Crypto", "Network", "Monitoring", "Response", "Recovery"]

# Rank risk so the backlog can break ties by risk after the gap.
RISK_RANK = {"high": 3, "medium": 2, "low": 1}

# The four scoped agents in the resilience improvement cycle (propose-only chain).
AGENT_CHAIN = ["monitor", "triage", "responder", "improver"]


# --------------------------------------------------------------------------- #
# Ingest — the MONITOR agent: read every evidence JSON into one dataset.
# --------------------------------------------------------------------------- #
def _load_source_files(src_dir):
    """Return a sorted list of (filename, parsed-json) for every *.json in src_dir."""
    out = []
    if not os.path.isdir(src_dir):
        return out
    for name in sorted(os.listdir(src_dir)):
        if not name.endswith(".json"):
            continue
        # Never ingest our own generated artefacts as if they were source evidence.
        if name in ("scorecard.json", "backlog.json", "dataset.json"):
            continue
        path = os.path.join(src_dir, name)
        try:
            with open(path, "r", encoding="utf-8") as f:
                out.append((name, json.load(f)))
        except (ValueError, OSError) as exc:  # pragma: no cover - defensive
            sys.stderr.write("skip %s: %s\n" % (name, exc))
    return out


def ingest(evidence_dir=None):
    """Build one dataset from the evidence.

    Reads evidence/ first; if it holds no source JSON, falls back to
    mock-data/sample-evidence/ so the lab runs before real evidence exists.
    Returns the dataset dict.
    """
    evidence_dir = evidence_dir or EVIDENCE_DIR
    files = _load_source_files(evidence_dir)
    source = "evidence"
    if not files:
        files = _load_source_files(SAMPLE_DIR)
        source = "sample-evidence"

    records = []
    for name, doc in files:
        if not isinstance(doc, dict):
            continue
        records.append({
            "file": name,
            "source_lab": doc.get("source_lab", "unknown"),
            "domain": doc.get("domain", "unknown"),
            "learning_outcome": doc.get("learning_outcome", "LO?"),
            "summary": doc.get("summary", ""),
            "maturity_current": int(doc.get("maturity_current", 0)),
            "maturity_target": int(doc.get("maturity_target", 0)),
            "risk": str(doc.get("risk", "medium")).lower(),
            "observation": doc.get("observation", ""),
            "improvement_hint": doc.get("improvement_hint", ""),
        })
    # Stable order: by fixed domain order, then by source lab name.
    records.sort(key=lambda r: (
        DOMAIN_ORDER.index(r["domain"]) if r["domain"] in DOMAIN_ORDER else 99,
        r["source_lab"],
    ))
    return {
        "input_source": source,
        "record_count": len(records),
        "records": records,
    }


# --------------------------------------------------------------------------- #
# Score — the TRIAGE agent: roll records up into a per-domain maturity scorecard.
# --------------------------------------------------------------------------- #
def score(dataset=None):
    """Return the resilience maturity scorecard (1-5) per control domain.

    current = min(current) across the domain's labs; target = max(target).
    """
    dataset = dataset or ingest()
    by_domain = {}
    for r in dataset["records"]:
        by_domain.setdefault(r["domain"], []).append(r)

    domains = []
    for name in DOMAIN_ORDER:
        recs = by_domain.get(name, [])
        if not recs:
            continue
        current = min(r["maturity_current"] for r in recs)
        target = max(r["maturity_target"] for r in recs)
        worst_risk = max((r["risk"] for r in recs), key=lambda x: RISK_RANK.get(x, 0))
        domains.append({
            "domain": name,
            "current": current,
            "target": target,
            "gap": target - current,
            "risk": worst_risk,
            "source_labs": sorted({r["source_lab"] for r in recs}),
            "evidence_count": len(recs),
        })

    return {
        "scale": "1-5 resilience maturity",
        "domains_order": [d["domain"] for d in domains],
        "current_profile": [d["current"] for d in domains],
        "target_profile": [d["target"] for d in domains],
        "domains": domains,
        "input_source": dataset["input_source"],
    }


# --------------------------------------------------------------------------- #
# Backlog — the RESPONDER agent: prioritise improvements by gap desc, then risk.
# --------------------------------------------------------------------------- #
def backlog(dataset=None):
    """Return the prioritised improvement backlog.

    Sorted by (target - current) gap DESC, then risk DESC. Each item maps back
    to its source lab(s) and to LO1/LO2/LO3. Items with gap 0 are dropped
    (already at target) but the domain is still recorded as 'at_target'.
    """
    dataset = dataset or ingest()
    sc = score(dataset)

    # LO per domain — taken from the evidence records feeding that domain.
    lo_by_domain = {}
    for r in dataset["records"]:
        lo_by_domain.setdefault(r["domain"], set()).add(r["learning_outcome"])
    hint_by_domain = {}
    for r in dataset["records"]:
        hint_by_domain.setdefault(r["domain"], []).append(r["improvement_hint"])

    items = []
    at_target = []
    for d in sc["domains"]:
        if d["gap"] <= 0:
            at_target.append(d["domain"])
            continue
        los = sorted(lo_by_domain.get(d["domain"], {"LO?"}))
        items.append({
            "domain": d["domain"],
            "gap": d["gap"],
            "current": d["current"],
            "target": d["target"],
            "risk": d["risk"],
            "risk_rank": RISK_RANK.get(d["risk"], 0),
            "source_labs": d["source_labs"],
            "maps_to_los": los,
            "recommended_actions": [h for h in hint_by_domain.get(d["domain"], []) if h],
            "requires_human_approval": True,
        })

    # gap DESC, then risk DESC, then fixed domain order for a stable tie-break.
    items.sort(key=lambda x: (
        -x["gap"],
        -x["risk_rank"],
        DOMAIN_ORDER.index(x["domain"]) if x["domain"] in DOMAIN_ORDER else 99,
    ))
    for i, it in enumerate(items, start=1):
        it["priority"] = i

    return {
        "generated_by": "responder-agent",
        "sort": "gap desc, then risk desc",
        "item_count": len(items),
        "items": items,
        "already_at_target": at_target,
    }


# --------------------------------------------------------------------------- #
# Report — the IMPROVER agent: board summary + human-approval gate (propose-only).
# --------------------------------------------------------------------------- #
def build_report(dataset=None):
    """Assemble the board-report structure, including proposed policy changes
    that are held for HUMAN APPROVAL (the improver only proposes)."""
    dataset = dataset or ingest()
    sc = score(dataset)
    bl = backlog(dataset)

    proposed_changes = []
    for it in bl["items"][:3]:  # top gaps become proposed policy changes
        proposed_changes.append({
            "domain": it["domain"],
            "change": "Raise %s maturity from %d to %d" % (
                it["domain"], it["current"], it["target"]),
            "source_labs": it["source_labs"],
            "maps_to_los": it["maps_to_los"],
            "requires_human_approval": True,
            "approval_status": "PENDING",
        })

    total_gap = sum(d["gap"] for d in sc["domains"])
    return {
        "title": "Cyber-Resilience Improvement Cycle — Board Report",
        "input_source": sc["input_source"],
        "scorecard": sc,
        "top_priorities": bl["items"][:3],
        "proposed_policy_changes": proposed_changes,
        "human_approval": {
            "required": True,
            "status": "PENDING",
            "statement": ("The improver agent PROPOSES the policy changes above. "
                          "A human reviewer MUST APPROVE them before this board "
                          "report is finalised or any change is applied."),
            "approver": "",
            "decision": "",
        },
        "totals": {
            "domains": len(sc["domains"]),
            "total_gap": total_gap,
            "at_target": bl["already_at_target"],
            "backlog_items": bl["item_count"],
        },
        "agent_chain": AGENT_CHAIN,
    }


def print_report(report):
    """Render the board report as readable text on stdout."""
    line = "=" * 70
    print(line)
    print(report["title"])
    print("Input source: %s" % report["input_source"])
    print(line)
    print()
    print("RESILIENCE MATURITY SCORECARD (1-5)")
    print("%-16s %8s %8s %6s  %s" % ("DOMAIN", "CURRENT", "TARGET", "GAP", "RISK"))
    print("-" * 70)
    for d in report["scorecard"]["domains"]:
        print("%-16s %8d %8d %6d  %s" % (
            d["domain"], d["current"], d["target"], d["gap"], d["risk"]))
    print("-" * 70)
    print("current profile: %s" % report["scorecard"]["current_profile"])
    print("target  profile: %s" % report["scorecard"]["target_profile"])
    print("total gap to close: %d" % report["totals"]["total_gap"])
    print()
    print("TOP IMPROVEMENT PRIORITIES (gap desc, then risk)")
    print("-" * 70)
    for it in report["top_priorities"]:
        print("  P%d  %-14s gap %d  risk %-6s  labs: %s  (%s)" % (
            it["priority"], it["domain"], it["gap"], it["risk"],
            ", ".join(it["source_labs"]), ", ".join(it["maps_to_los"])))
    print()
    print("PROPOSED POLICY CHANGES (improver agent — PROPOSE ONLY)")
    print("-" * 70)
    for c in report["proposed_policy_changes"]:
        print("  [%s] %s  <- %s" % (
            c["approval_status"], c["change"], ", ".join(c["source_labs"])))
    print()
    ha = report["human_approval"]
    print("HUMAN APPROVAL GATE")
    print("-" * 70)
    print("  required: %s   status: %s" % (ha["required"], ha["status"]))
    print("  %s" % ha["statement"])
    print()
    print(line)
    print("This report is DRAFT until a human approves the proposed changes above.")
    print(line)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Multi-agent cyber-resilience improvement cycle (Lab 10 capstone).")
    ap.add_argument("--ingest", metavar="DIR", nargs="?", const=EVIDENCE_DIR,
                    help="build one dataset from the evidence directory "
                         "(falls back to mock-data/sample-evidence/ if empty)")
    ap.add_argument("--score", action="store_true",
                    help="print the resilience maturity scorecard as JSON")
    ap.add_argument("--backlog", action="store_true",
                    help="print the prioritised improvement backlog as JSON")
    ap.add_argument("--report", action="store_true",
                    help="print the board-ready summary (with human-approval gate)")
    args = ap.parse_args(argv)

    if args.ingest is not None:
        ds = ingest(args.ingest)
        print(json.dumps(ds, indent=2))
        sys.stderr.write("ingested %d record(s) from %s\n" % (
            ds["record_count"], ds["input_source"]))
        return 0
    if args.score:
        print(json.dumps(score(), indent=2))
        return 0
    if args.backlog:
        print(json.dumps(backlog(), indent=2))
        return 0
    if args.report:
        print_report(build_report())
        return 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
