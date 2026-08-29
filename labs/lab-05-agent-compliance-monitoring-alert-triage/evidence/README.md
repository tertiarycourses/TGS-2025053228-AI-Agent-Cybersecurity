# Lab 5 — Evidence to Capture

Save your work here as you go. **Do not include model answers** — capture *your* outputs
and prompts so an assessor can see the workflow. Never store real secrets or personal data.

Capture:

1. **Compliance report** — `compliance-report.json` produced by
   `compliance_check.py --policy … --audit …`, showing **7 violations (2 CRITICAL)** and
   the by-severity line `Critical=2, High=5, Medium=9, Low=12, Info=7`.
2. **Alert queue** — `alert-queue.json` produced by `triage.py`, showing **35 alerts**
   ordered highest-risk first, each with an `audit_line` citation and `observation`
   separate from `inference`.
3. **Agent transcript (with citations)** — the Hermes "Alert triage" prompt and its JSON
   output, showing every alert **cites its audit line**, keeps **observation vs
   inference**, and that **no containment was applied without approval**. Optionally the
   OpenClaw compliance-review transcript confirming the two criticals.
4. **Human-approval record** — a short note, per **Critical** alert, of whether you
   approved or rejected the proposed containment and why (nothing is contained without
   this).
5. **Acceptance** — the `verify.py` output ending in `RESULT: PASS`.

Suggested filenames: `compliance-report.json`, `alert-queue.json`,
`03-compliance.txt`, `05-hermes-triage.json`, `06-openclaw-review.json`,
`07-approvals.md`, `08-verify.txt`.
