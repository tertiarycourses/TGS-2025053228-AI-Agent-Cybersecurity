#!/usr/bin/env python3
"""compliance_check.py — monitor a logged AI-agent action stream against policy.

Standard library only (json, csv, argparse). Reads a YAML agent policy and a JSONL
audit log (one logged agent action per line) and produces a compliance report that
flags every action which:
  (a) used a tool OUTSIDE the acting agent's allow-list        -> out_of_scope_tool
  (b) skipped a required approval on a state-changing action   -> missing_approval
  (c) touched Confidential data without a control              -> unprotected_confidential

Every flagged finding is scored (severity x confidence) and — crucially — carries the
exact audit line index it came from, so nothing is ever fabricated: a finding is only
ever a citation of a real logged line.

Two modes (the EXACT commands the lab uses):

  # 1. analyse the audit stream against the policy, write the compliance report
  python3 compliance_check.py --policy mock-data/policy.yaml --audit mock-data/agent-audit.jsonl

  # 2. re-print / summarise a report that was already written
  python3 compliance_check.py --report evidence/compliance-report.json

The report is written to evidence/compliance-report.json (deterministic ordering).
"""
import argparse, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import miniyaml

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_REPORT = os.path.join(HERE, "evidence", "compliance-report.json")

# ---------------------------------------------------------------------------
# Severity model. Each logged action is graded into exactly ONE severity so the
# downstream alert queue is deterministic. The grade is decided ONLY by what the
# log line + the policy show — never by guesswork.
#
#   CRITICAL  an out-of-scope tool call, or a missing approval on a state-changing
#             action (a control was bypassed — highest priority)
#   HIGH      Confidential data touched with NO control recorded on the action
#   MEDIUM    a compliant but sensitive action on Confidential data (watch item)
#   LOW       a compliant action on Internal data
#   INFO      a compliant action on Public/None data (routine, logged for audit)
#
# severity weight x confidence gives the triage score in triage.py.
# ---------------------------------------------------------------------------
SEVERITY_WEIGHT = {"Critical": 100, "High": 40, "Medium": 20, "Low": 8, "Info": 2}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def load_policy(path):
    return miniyaml.load(path)


def _policy_index(policy):
    """Return lookups derived from the policy:
    tools_by_agent[agent]        -> set of allowed tool names
    approval_required[asset]     -> True if the asset needs human approval
    confidential[asset]          -> True if the asset is Confidential
    state_changing[asset]        -> True if touching it changes state
    """
    tools_by_agent, approval, confidential, statechg = {}, {}, {}, {}
    for a in policy.get("agents", []) or []:
        tools_by_agent[a.get("name")] = set(a.get("allowed_tools") or [])
    for a in policy.get("assets", []) or []:
        name = a.get("name")
        confidential[name] = (a.get("classification") == "Confidential")
        statechg[name] = (a.get("state_changing") is True)
        approval[name] = (str(a.get("human_approval", "")).strip() == "required")
    return tools_by_agent, approval, confidential, statechg


def evaluate_line(idx, action, tools_by_agent, approval, confidential, statechg):
    """Grade a single logged action. Returns a finding dict (always — even INFO,
    so every audit line is accounted for and citable). `idx` is the 0-based line
    index in the audit file, echoed back as `audit_line` for the citation.
    """
    agent = action.get("agent")
    tool = action.get("tool")
    target = action.get("target")
    approved = bool(action.get("approved"))
    classification = action.get("classification")
    control = str(action.get("control", "")).strip()  # "" / "none" == no control
    has_control = control not in ("", "none")

    allowed = tools_by_agent.get(agent, set())
    needs_approval = approval.get(target, False) or (statechg.get(target, False))
    is_conf = confidential.get(target, False) or (classification == "Confidential")

    violations = []          # rule ids that fired, e.g. ["V1"]
    severity = None
    reason = None

    # (a) out-of-scope tool call -> CRITICAL
    if allowed and tool not in allowed:
        violations.append("V1_out_of_scope_tool")
        severity = "Critical"
        reason = f"agent '{agent}' used tool '{tool}' which is outside its allow-list {sorted(allowed)}"

    # (b) missing approval on a state-changing action -> CRITICAL
    if (statechg.get(target, False) or needs_approval) and not approved:
        violations.append("V2_missing_approval")
        if severity != "Critical":
            severity = "Critical"
            reason = f"state-changing action on '{target}' proceeded WITHOUT the required human approval"

    # (c) Confidential data touched with no control -> HIGH
    if is_conf and not has_control:
        violations.append("V3_unprotected_confidential")
        if severity is None:
            severity = "High"
            reason = f"Confidential target '{target}' was accessed with no control recorded on the action"

    # ---- compliant actions still emit an observation, graded by sensitivity ----
    if severity is None:
        if is_conf:
            severity = "Medium"
            reason = f"compliant sensitive action on Confidential target '{target}' (approved, control='{control}')"
        elif classification == "Internal":
            severity = "Low"
            reason = f"compliant action on Internal target '{target}'"
        else:  # Public / None
            severity = "Info"
            reason = f"routine compliant action on {classification or 'None'} target '{target}'"

    # confidence: how sure are we, from the log alone, that the grade is right?
    #   a hard rule fired on structured fields -> very high; a compliant observation
    #   is certain too (nothing is inferred). Confidence never invents facts.
    confidence = 0.99 if violations else 0.97

    return {
        "audit_line": idx,                 # 0-based index into agent-audit.jsonl
        "ts": action.get("ts"),
        "agent": agent,
        "tool": tool,
        "target": target,
        "classification": classification,
        "approved": approved,
        "control": control or "none",
        "severity": severity,
        "violations": violations,
        "is_violation": bool(violations),
        "confidence": confidence,
        "observation": _observation(action, idx),
        "reason": reason,
    }


def _observation(action, idx):
    """A neutral restatement of what the log LINE shows — no interpretation."""
    return (f"line {idx}: agent={action.get('agent')} tool={action.get('tool')} "
            f"target={action.get('target')} approved={action.get('approved')} "
            f"classification={action.get('classification')} control={action.get('control','none')}")


def read_audit(path):
    """Read the JSONL audit log -> list of (idx, action). Blank lines are skipped
    but do NOT advance the citable index, so `audit_line` always maps back to the
    Nth data record (which is what the learner counts)."""
    actions = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            actions.append(json.loads(raw))
    return list(enumerate(actions))


def analyse(policy_path, audit_path):
    policy = load_policy(policy_path)
    tools_by_agent, approval, confidential, statechg = _policy_index(policy)
    findings = []
    for idx, action in read_audit(audit_path):
        findings.append(evaluate_line(idx, action, tools_by_agent, approval, confidential, statechg))

    by_sev = {s: 0 for s in SEVERITY_ORDER}
    for fi in findings:
        by_sev[fi["severity"]] += 1
    violations = [f for f in findings if f["is_violation"]]

    report = {
        "policy": policy.get("policy_name", "AI Agent Compliance Policy"),
        "audit_file": os.path.basename(audit_path),
        "total_actions": len(findings),
        "total_violations": len(violations),
        "critical_violations": sum(1 for f in violations if f["severity"] == "Critical"),
        "by_severity": by_sev,
        "severity_weight": SEVERITY_WEIGHT,
        "findings": findings,
    }
    return report


def print_summary(report):
    print(f"COMPLIANCE CHECK — {report['policy']}")
    print(f"  audit file        : {report['audit_file']}")
    print(f"  actions analysed  : {report['total_actions']}")
    print(f"  violations flagged: {report['total_violations']} "
          f"({report['critical_violations']} CRITICAL)")
    print("  by severity       : " +
          ", ".join(f"{s}={report['by_severity'][s]}" for s in SEVERITY_ORDER))
    crit = [f for f in report["findings"] if f["severity"] == "Critical"]
    if crit:
        print("  CRITICAL findings (each cites its audit line):")
        for f in crit:
            print(f"    ✗ line {f['audit_line']}: {', '.join(f['violations'])} — {f['reason']}")


def main():
    ap = argparse.ArgumentParser(description="Monitor an AI-agent audit stream against policy.")
    ap.add_argument("--policy", metavar="YAML", help="the agent policy (YAML)")
    ap.add_argument("--audit", metavar="JSONL", help="the agent audit log (one action per line)")
    ap.add_argument("--report", metavar="JSON", help="re-print an existing compliance report")
    ap.add_argument("--out", metavar="JSON", default=DEFAULT_REPORT,
                    help="where to write the report (default evidence/compliance-report.json)")
    args = ap.parse_args()

    if args.report:
        with open(args.report, "r", encoding="utf-8") as f:
            report = json.load(f)
        print_summary(report)
        return 0

    if args.policy and args.audit:
        report = analyse(args.policy, args.audit)
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print_summary(report)
        print(f"\nWrote {args.out}")
        return 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
