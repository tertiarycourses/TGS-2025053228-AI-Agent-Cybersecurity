# Lab 1 — Evidence to Capture

Save your work here as you go. **Do not include model answers** — capture *your* outputs
and prompts so an assessor can see the workflow. Never store real secrets or personal data.

Capture:

1. **Asset classification** — the output of `policy_lint.py --classify ...` (screenshot or
   text), showing which assets are Confidential.
2. **Your `policy.yaml`** — the policy you drafted/extended (a copy placed here is fine).
3. **`trust-boundary.json`** — produced by `trust_boundary.py`, plus your diagram if you
   drew one in diagrams.net.
4. **Lint result** — the `policy_lint.py --check policy.yaml` output showing **0 violations**.
5. **Agent transcript** — the OpenClaw policy-review prompt and its JSON output, showing
   cited findings and that **no change was applied without approval**.
6. **Human-approval record** — a short note of which proposed change you approved/rejected
   and why.
7. **Acceptance** — the `verify.py` output ending in `RESULT: PASS`.

Suggested filenames: `01-classify.txt`, `policy.yaml`, `trust-boundary.json`,
`04-lint.txt`, `05-openclaw-review.json`, `06-approvals.md`, `08-verify.txt`.
