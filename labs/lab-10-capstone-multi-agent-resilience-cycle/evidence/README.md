# Lab 10 — Evidence to Capture

Save your work here as you go. **Do not include model answers** — capture *your* outputs
and prompts so an assessor can see the workflow. Never store real secrets or personal data.

This folder is also the **ingest source**: `capstone.py --ingest evidence/` reads the
JSON here first, and **falls back** to `mock-data/sample-evidence/` when `evidence/` holds
no source evidence yet. If you carried your own roll-ups over from Labs 1–9, drop them here
as one JSON per source lab (same shape as the shipped samples).

Capture:

1. **Scorecard** — `scorecard.json` from `python3 capstone.py --score > evidence/scorecard.json`,
   showing all six domains with current `[3,3,4,2,3,2]` and target `[4,4,4,4,4,3]`.
2. **Backlog** — `backlog.json` from `python3 capstone.py --backlog > evidence/backlog.json`,
   showing the gap-descending order (Monitoring first) with each item traceable to a source
   lab and to LO1/LO2/LO3.
3. **Board report** — the text of `python3 capstone.py --report` (screenshot or saved
   output), including the PROPOSED POLICY CHANGES block and the HUMAN APPROVAL GATE.
4. **Per-agent transcripts** — the Hermes orchestration (monitor → triage → responder →
   improver) and the OpenClaw review, showing each agent **cited its source lab/evidence**,
   separated **observation from recommendation**, and used **only its scoped tools**.
5. **Human-approval record** — a short note of which proposed changes you **approved or
   rejected** and why. Confirm the improver only *proposed* and did **not** apply a change
   or remove an approval gate.
6. **Acceptance** — the `verify.py` output ending in `RESULT: PASS`.

Suggested filenames: `scorecard.json`, `backlog.json`, `03-board-report.txt`,
`04-hermes-orchestration.json`, `05-openclaw-review.json`, `06-approvals.md`,
`08-verify.txt`.
