# Lab 7 — Evidence to Capture

Save your work here as you go. **Do not include model answers** — capture *your* outputs
and prompts so an assessor can see the workflow. Never store real capture data, IP
addresses or personal data.

Capture:

1. **Firewall summary** — the output of `log_investigate.py --fw mock-data/firewall.log`
   (screenshot or text), showing the DENY counts by destination port and by source.
2. **`timeline.json`** — produced by `--detect-bruteforce`, showing the brute-force
   source+port, the observation log lines, and the "attempted RDP brute force" inference.
3. **Auth confirmation** — the output of `log_investigate.py --auth mock-data/auth.log`,
   showing **no successful login** from the attacker IP (segmentation blocked it).
4. **Agent transcript** — the OpenClaw investigation prompt and/or the Hermes
   investigation note with their JSON output, showing that **every claim cites the exact
   log line** and that **observation is kept separate from inference**.
5. **Human-approval record** — a short note of which proposed detection rule you
   approved or rejected and why. **Nothing is "deployed" without your approval.**
6. **Acceptance** — the `verify.py` output ending in `RESULT: PASS`.

Suggested filenames: `02-fw-summary.txt`, `timeline.json`, `04-auth.txt`,
`05-openclaw-investigation.json`, `06-hermes-note.json`, `07-approvals.md`,
`08-verify.txt`.
