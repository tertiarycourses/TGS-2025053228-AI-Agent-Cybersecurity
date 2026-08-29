# Lab 9 — Evidence to Capture

Save your work here as you go. **Do not include model answers** — capture *your* outputs
and prompts so an assessor can see the workflow. Never store real secrets, host names or
personal data.

Capture:

1. **IR timeline** — `timeline.json` produced by `ir_timeline.py`, showing all **six IR
   phases in order** and each entry keeping observation separate from inference.
2. **Chain of custody** — `custody.csv` produced by `forensics.py --preserve`, one
   SHA-256 per artifact, plus a note showing that **re-running reproduced identical hashes**
   (integrity held).
3. **Recovery plan** — `recovery-plan.json` produced by `dr_plan.py`, showing the
   **RTO-ascending restore order** and each system's backup frequency.
4. **Agent transcript (IR plan)** — the Hermes "IR plan" prompt and its JSON output,
   showing each step **cites the timeline entry** and separates observation from inference.
5. **Approval records** — for **each gated state-changing step** (isolate host, rotate
   credentials, restore backup) a short record of who approved/rejected it and why, showing
   the agent only **proposed** and nothing was applied without approval.
6. **Agent transcript (forensic review)** — the OpenClaw "Forensic evidence review" prompt
   and its JSON output, with findings cited to the custody rows.
7. **Acceptance** — the `verify.py` output ending in `RESULT: PASS`.

Suggested filenames: `timeline.json`, `custody.csv`, `03-custody-rerun.txt`,
`recovery-plan.json`, `06-hermes-ir-plan.json`, `06-approvals.md`,
`07-openclaw-forensics.json`, `08-verify.txt`.
