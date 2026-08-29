# Lab 4 — Evidence to Capture

Save your work here as you go. **Do not include model answers** — capture *your* outputs
and prompts so an assessor can see the workflow. Never store real IP plans, secrets or
personal data.

Capture:

1. **Subnet plan** — the output of `subnet_plan.py --need mock-data/zone-requirements.csv`
   (screenshot or text), showing the four zones sized to `/27,/28,/29,/30` with usable
   counts **[30, 14, 6, 2]** and **no overlaps**. Include your IP Subnet Calculator check.
2. **Your `subnets.csv`** — the plan you recorded (a copy placed here is fine), plus the
   `subnet_plan.py --check subnets.csv` output showing **0 problems**, and the
   `--check mock-data/subnets.bad.csv` output showing the **OVERLAP** being caught.
3. **Segmentation diagram** — the four zones and allowed flows drawn in diagrams.net
   (agent_runtime → tool_sandbox :443, the management paths, and the single approved
   management → sensitive_data path; every other arrow into sensitive_data marked denied).
4. **fw_validate result** — the `fw_validate.py --policy segmentation-policy.yaml
   firewall-rules.csv` output showing the **flagged** `tool_sandbox → sensitive_data`
   rule and its cited policy basis.
5. **Agent transcript** — the OpenClaw segmentation-review prompt and its JSON output,
   showing the **cited policy line** for each denied flow, observation separated from
   inference, and that **no rule was added without approval**.
6. **Human-approval record** — a short note of which proposed fix you approved/rejected
   and why (especially any request to open a path into `sensitive_data`).
7. **Acceptance** — the `verify.py` output ending in `RESULT: PASS`.

Suggested filenames: `01-plan.txt`, `subnets.csv`, `02-check.txt`, `03-diagram.png`,
`04-fw-validate.txt`, `05-openclaw-review.json`, `06-approvals.md`, `10-verify.txt`.
