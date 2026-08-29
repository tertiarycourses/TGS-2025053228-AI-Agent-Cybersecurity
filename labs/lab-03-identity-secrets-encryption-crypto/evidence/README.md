# Lab 3 — Evidence to Capture

Save your work here as you go. **Do not include model answers** — capture *your* outputs
and prompts so an assessor can see the workflow. **Never store a real secret or personal
data**, and never store an un-redacted secret value.

Capture:

1. **Redacted secret-scan report** — the output of `secret_scan.py mock-data/agent-config/`
   (screenshot or text), showing the **5 findings** by file + line with values **redacted**.
   Confirm no raw secret is visible.
2. **Hash-vs-encrypt classification** — the output of `crypto_check.py --classify ...`,
   showing which items are HASH and which are ENCRYPT (and why).
3. **Password-entropy report** — the output of `crypto_check.py --entropy ...`, showing the
   entropy in bits per tier and the **WEAK** flags below the policy floor (passwords redacted).
4. **Certificate result** — the output of `crypto_check.py --cert ...`, showing the
   issuer/subject/validity/key-size and the **EXPIRED** status.
5. **Agent transcript** — the OpenClaw secrets-review prompt and its JSON output, showing
   **cited file + line**, **no secret echoed**, and that **no change was applied without
   approval**.
6. **Human-approval record** — a short note of which proposed action you approved/rejected
   (e.g. "approve: rotate cloud key; defer: revoke cert") and why. Rotate/revoke are
   propose-only until a human signs off.
7. **Acceptance** — the `verify.py` output ending in `RESULT: PASS`.

Suggested filenames: `01-secret-scan.txt`, `02-classify.txt`, `03-entropy.txt`,
`04-cert.txt`, `05-openclaw-review.json`, `06-approvals.md`, `07-verify.txt`.
