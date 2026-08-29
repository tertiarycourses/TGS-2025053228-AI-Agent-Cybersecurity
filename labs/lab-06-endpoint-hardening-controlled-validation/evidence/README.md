# Lab 6 — Evidence to Capture

Save your work here as you go. **Do not include model answers** — capture *your* outputs
and prompts so an assessor can see the workflow. Never store real secrets or personal data.

Capture:

1. **Fleet inventory** — the output of `harden_check.py --inventory ...` (screenshot or
   text), showing the 100 synthetic endpoints.
2. **Scored posture** — the `harden_check.py --score ...` output **and** `posture.json`
   (from `--json`), showing the per-control pass rates (72 / 65 / 88 / 54 / 41), the
   fleet posture and the weakest controls.
3. **Baseline** — your `baseline.yaml` (a copy placed here is fine), showing all 5 K2
   controls set `required: true`.
4. **Controlled-validation note** — a short note confirming any live check stayed on the
   **authorized Ethical Hacking Trainer** target, used **read-only** checks only, and
   involved **no exploitation** (no real/internet host).
5. **Remediation plan** — the propose-only plan for the weakest controls, each item
   citing the failing check, mapped to a BYOD/remote-work risk, and marked **human
   approval required**.
6. **Agent transcript** — the OpenClaw remediation prompt and its JSON output, showing
   cited findings and that **no change was applied without approval**.
7. **Human-approval record** — a short note of which proposed hardening change you
   approved/rejected and why.
8. **Acceptance** — the `verify.py` output ending in `RESULT: PASS`.

Suggested filenames: `01-inventory.txt`, `posture.json`, `baseline.yaml`,
`04-validation-note.md`, `05-remediation-plan.json`, `06-openclaw-transcript.json`,
`07-approvals.md`, `08-verify.txt`.
