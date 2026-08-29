#!/usr/bin/env python3
"""triage.py — score compliance findings and emit an alert queue.

Standard library only (json). Reads the compliance report produced by
compliance_check.py and turns every finding into an ALERT, scored by
severity x confidence, ordered highest-risk first.

Each alert deliberately keeps two things apart:
  * observation  — what the audit LINE literally shows (facts only)
  * inference    — the suspected cause / risk (clearly marked, never asserted as fact)

Every alert cites the exact audit line index it came from (`audit_line`). No alert
is ever produced without a real line behind it, and the triage NEVER proposes a
containment action on its own — remediation is a human-approval step.

Usage (the EXACT command the lab uses):

  python3 triage.py evidence/compliance-report.json > evidence/alert-queue.json
"""
import json, sys

# severity x confidence -> a single risk score used purely for ORDER within the
# queue. The severity bucket itself is decided upstream in compliance_check.py.
SEVERITY_WEIGHT = {"Critical": 100, "High": 40, "Medium": 20, "Low": 8, "Info": 2}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

VIOLATION_INFERENCE = {
    "V1_out_of_scope_tool":
        "SUSPECTED: the agent invoked a tool outside its allow-list — possible mis-scoped "
        "permission or prompt-injection steering it to an unauthorised capability.",
    "V2_missing_approval":
        "SUSPECTED: a state-changing action ran without the human-approval gate — possible "
        "bypassed control or a broken approval workflow.",
    "V3_unprotected_confidential":
        "SUSPECTED: Confidential data was handled with no control recorded — possible missing "
        "encryption/access control on the action path.",
}

RECOMMENDED_ACTION = {
    "Critical": "PROPOSE containment (e.g., suspend the agent's tool token) — HOLD for human approval.",
    "High":     "PROPOSE review of the control gap — HOLD for human approval.",
    "Medium":   "Queue for analyst review; no automated action.",
    "Low":      "Log and monitor; no action.",
    "Info":     "Retain for audit trail; no action.",
}


def infer(finding):
    """Build the INFERENCE text. For a compliant observation there is nothing to
    suspect, so we say so plainly rather than invent a cause."""
    if not finding.get("violations"):
        return "No violation on this line; recorded as a compliant observation for the audit trail."
    parts = [VIOLATION_INFERENCE.get(v, f"SUSPECTED issue: {v}") for v in finding["violations"]]
    return " ".join(parts)


def to_alert(finding):
    sev = finding["severity"]
    conf = float(finding.get("confidence", 0.0))
    score = round(SEVERITY_WEIGHT.get(sev, 0) * conf, 3)
    return {
        "alert_id": f"ALERT-{finding['audit_line']:04d}",
        "audit_line": finding["audit_line"],          # exact citation into agent-audit.jsonl
        "severity": sev,
        "confidence": conf,
        "score": score,                               # severity_weight x confidence
        "is_violation": finding.get("is_violation", False),
        "violations": finding.get("violations", []),
        # --- observation kept strictly separate from inference ---
        "observation": finding.get("observation"),    # what the log line shows (facts)
        "inference": infer(finding),                   # suspected cause (marked SUSPECTED)
        "recommended_action": RECOMMENDED_ACTION.get(sev, "Queue for review."),
        "requires_human_approval": sev in ("Critical", "High"),
        "auto_contained": False,                       # triage NEVER contains on its own
    }


def triage(report):
    alerts = [to_alert(f) for f in report.get("findings", [])]
    # order: severity rank, then score desc, then audit_line for stable output
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    alerts.sort(key=lambda a: (rank.get(a["severity"], 99), -a["score"], a["audit_line"]))

    by_sev = {s: 0 for s in SEVERITY_ORDER}
    for a in alerts:
        by_sev[a["severity"]] += 1

    return {
        "source_report": report.get("audit_file"),
        "policy": report.get("policy"),
        "total_alerts": len(alerts),
        "by_severity": by_sev,
        "critical": [a["alert_id"] for a in alerts if a["severity"] == "Critical"],
        "human_approval_required": [a["alert_id"] for a in alerts if a["requires_human_approval"]],
        "note": ("Triage is PROPOSE-ONLY. No containment action is taken automatically; "
                 "every Critical/High alert is HELD for human approval."),
        "alerts": alerts,
    }


def main(argv):
    if len(argv) < 2:
        print("usage: python3 triage.py <compliance-report.json>  > alert-queue.json", file=sys.stderr)
        return 2
    with open(argv[1], "r", encoding="utf-8") as f:
        report = json.load(f)
    queue = triage(report)
    # emit the alert queue to stdout (the lab redirects it to evidence/alert-queue.json)
    print(json.dumps(queue, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
