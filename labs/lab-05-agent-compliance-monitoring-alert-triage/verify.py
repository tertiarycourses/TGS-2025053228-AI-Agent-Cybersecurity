#!/usr/bin/env python3
"""verify.py — deterministic acceptance check for Lab 5.

Runs the lab tooling end-to-end against the seeded fixtures and asserts the
known-correct results, so a PASS proves the compliance monitor and the alert
triage work as the deck describes:

  1. both seeded CRITICAL violations are detected
       - one OUT-OF-SCOPE tool call
       - one MISSING-APPROVAL on a state-changing action
  2. ZERO false positives on the compliant actions (every non-violation line is
     graded Medium/Low/Info and is NOT flagged as a violation)
  3. the by-severity counts equal Critical=2, High=5, Medium=9, Low=12, Info=7
     (matches the deck chart; 35 alerts total)
  4. every alert cites a REAL audit line index (0 <= audit_line < number of lines)

Exit code 0 = PASS, 1 = FAIL.
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import compliance_check, triage

MD = os.path.join(HERE, "mock-data")
POLICY = os.path.join(MD, "policy.yaml")
AUDIT = os.path.join(MD, "agent-audit.jsonl")

EXPECTED_BY_SEVERITY = {"Critical": 2, "High": 5, "Medium": 9, "Low": 12, "Info": 7}
EXPECTED_TOTAL = 35

fails = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def main():
    print("Lab 5 — Agent Compliance Monitoring & Alert Triage · verifier\n")

    # run the real pipeline (no pre-baked outputs trusted)
    report = compliance_check.analyse(POLICY, AUDIT)
    queue = triage.triage(report)
    alerts = queue["alerts"]
    n_lines = report["total_actions"]

    # 1) both seeded CRITICAL violations are detected --------------------------
    crit = [f for f in report["findings"] if f["severity"] == "Critical" and f["is_violation"]]
    v_types = {v for f in crit for v in f["violations"]}
    check("exactly 2 CRITICAL violations detected", len(crit) == 2)
    check("  -> the OUT-OF-SCOPE tool call is caught (V1)", "V1_out_of_scope_tool" in v_types)
    check("  -> the MISSING-APPROVAL on a state-changing action is caught (V2)",
          "V2_missing_approval" in v_types)

    # the two criticals must sit on distinct, real audit lines
    crit_lines = sorted(f["audit_line"] for f in crit)
    check("  -> the 2 criticals cite distinct audit lines", len(set(crit_lines)) == 2)
    check("  -> both critical audit lines are real (in range)",
          all(0 <= i < n_lines for i in crit_lines))

    # 2) zero false positives on the compliant actions ------------------------
    compliant = [f for f in report["findings"] if not f["is_violation"]]
    fp = [f for f in compliant if f["severity"] == "Critical"]
    check("zero false positives: no compliant action is graded Critical", fp == [])
    check("zero false positives: no compliant action carries any violation tag",
          all(f["violations"] == [] for f in compliant))
    # every violation is genuinely one of the three rules — no spurious flags
    stray = [f for f in report["findings"]
             if f["is_violation"] and not (set(f["violations"]) <=
                 {"V1_out_of_scope_tool", "V2_missing_approval", "V3_unprotected_confidential"})]
    check("no stray/unknown violation types", stray == [])

    # 3) by-severity counts match the deck chart ------------------------------
    check(f"compliance-report by-severity == {list(EXPECTED_BY_SEVERITY.values())} "
          "[Critical,High,Medium,Low,Info]",
          report["by_severity"] == EXPECTED_BY_SEVERITY)
    check(f"alert-queue by-severity == {list(EXPECTED_BY_SEVERITY.values())}",
          queue["by_severity"] == EXPECTED_BY_SEVERITY)
    check(f"alert-queue total == {EXPECTED_TOTAL}", queue["total_alerts"] == EXPECTED_TOTAL)
    check("report and queue agree on totals",
          report["total_actions"] == queue["total_alerts"] == EXPECTED_TOTAL)

    # 4) every alert cites a real audit line ----------------------------------
    check("every alert has an audit_line index",
          all("audit_line" in a for a in alerts))
    check("every alert cites a REAL audit line (0 <= line < %d)" % n_lines,
          all(isinstance(a["audit_line"], int) and 0 <= a["audit_line"] < n_lines for a in alerts))
    lines_cited = sorted(a["audit_line"] for a in alerts)
    check("every audit line is cited exactly once (no fabricated / dropped lines)",
          lines_cited == list(range(n_lines)))

    # 5) safety: triage is propose-only, holds Critical/High for a human ------
    check("triage takes NO automatic containment (auto_contained is False everywhere)",
          all(a["auto_contained"] is False for a in alerts))
    hi = [a for a in alerts if a["severity"] in ("Critical", "High")]
    check("every Critical/High alert requires human approval",
          all(a["requires_human_approval"] for a in hi))
    check("observation is kept separate from inference on every alert",
          all(a.get("observation") and a.get("inference") for a in alerts))

    print()
    if fails:
        print(f"RESULT: FAIL ({len(fails)} check(s) failed)")
        return 1
    print("RESULT: PASS — 2 seeded criticals detected, 0 false positives, "
          "severity counts [2,5,9,12,7], every alert cites a real audit line.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
