# Lab 4 — Network Segmentation & IP Policy

**Topic 1 · LO2 · Assessment criteria K2, A2**

> Carve an AI-agent network into least-privilege **zones**, right-size each zone's
> **subnet** from a single supernet with no overlaps, express the allowed inter-zone
> flows as a **machine-checkable** policy, and prove a firewall rule set enforces it —
> catching any rule that would breach the segmentation.

## Safety boundary

This lab uses **synthetic data only** (`mock-data/`). No live systems are touched and
no packets are sent — the tools reason about CIDRs and rules as text. The agent
**proposes**; a **human approves** before any new inter-zone rule would be added. Never
paste real IP plans, credentials or personal data into a prompt, a log or `evidence/`.

## What you'll build

- `subnets.csv` — the right-sized, non-overlapping subnet plan for the 4 zones
- `segmentation-policy.yaml` — the allowed inter-zone flows (least privilege)
- `firewall-rules.csv` — a rule set validated against the policy (one seeded violation)
- A passing `python3 verify.py` acceptance report

## Prerequisites

- Python 3 (standard library only — nothing to install; uses the `ipaddress` module)
- The **IP Subnet Calculator**: <https://alfredang.github.io/ipcalculator/>
- An OpenClaw workspace (for the segmentation-review prompt in `AI-PROMPTS.md`)
- diagrams.net (optional, to draw the segmentation diagram)

## Files

| File | Purpose |
|---|---|
| `subnet_plan.py` | Propose right-sized subnets (`--need`) and validate a plan (`--check`) |
| `fw_validate.py` | Validate `firewall-rules.csv` against the segmentation policy |
| `miniyaml.py` | Tiny standard-library YAML-subset loader (no third-party deps) |
| `verify.py` | Deterministic acceptance check |
| `segmentation-policy.yaml` | Allowed inter-zone flows (least privilege, default-deny) |
| `firewall-rules.csv` | The firewall rule set (contains one seeded violation to find) |
| `subnets.csv` | The right-sized subnet plan you validate and ship |
| `mock-data/zone-requirements.csv` | Zones + required host counts (the starting brief) |
| `mock-data/subnets.solution.csv` | A correct plan (used by the verifier) |
| `mock-data/subnets.bad.csv` | A plan with a deliberate overlap (used by the verifier) |
| `AI-PROMPTS.md` | Reusable OpenClaw/Hermes prompts + guardrails |
| `evidence/README.md` | What to capture as evidence |

## The zones

The AI-agent estate is one supernet — **`10.20.0.0/24`** — carved into four zones:

| Zone | Needs (hosts) | Right-size | Usable |
|---|---|---|---|
| `agent_runtime` (LLM workers + orchestrator) | ~30 | `/27` | **30** |
| `tool_sandbox` (isolated tool/code execution) | ~14 | `/28` | **14** |
| `sensitive_data` (records + secrets store) | ~6 | `/29` | **6** |
| `management` (admin jump host + approval console) | ~2 | `/30` | **2** |

`sensitive_data` is protected: **nothing** may reach it except the **approved management
path**. The chart uses usable-host counts **[30, 14, 6, 2]** for `/27, /28, /29, /30`.

## Steps

### 1 — Read the zone brief and propose a subnet plan

```bash
python3 subnet_plan.py --need mock-data/zone-requirements.csv
```

**Expected:** four subnets, largest zone first, carved from `10.20.0.0/24` with **no
overlaps** and usable-host counts **[30, 14, 6, 2]** for `/27, /28, /29, /30`.

### 2 — Check the sizing in the IP Subnet Calculator

Open <https://alfredang.github.io/ipcalculator/> and enter each CIDR
(`10.20.0.0/27`, `10.20.0.32/28`, `10.20.0.48/29`, `10.20.0.56/30`). Confirm the
**usable host** count and the network/broadcast/gateway addresses match the plan.

### 3 — Record the plan

Copy the proposed rows into `subnets.csv` (columns `zone,cidr,usable,gateway`). A
correct starter is already shipped; a reference copy lives at
`mock-data/subnets.solution.csv`.

### 4 — Validate the plan (sizing + no overlaps)

```bash
python3 subnet_plan.py --check subnets.csv
```

**Expected:** `0 problems` and **exit code 0**. Now try the broken plan to see overlap
detection fire:

```bash
python3 subnet_plan.py --check mock-data/subnets.bad.csv
```

**Expected:** it reports `OVERLAP: agent_runtime 10.20.0.0/27 overlaps tool_sandbox
10.20.0.16/28` and **exits 1**.

### 5 — Draw the segmentation diagram

Render the four zones and the allowed flows (in diagrams.net). Draw
`agent_runtime → tool_sandbox :443`, the `management` SSH paths, and the single
`management → sensitive_data :443` approved path. Mark every other arrow into
`sensitive_data` as **denied**.

### 6 — Read the segmentation policy

Open `segmentation-policy.yaml`. `default_action: deny` means **anything not listed is
denied**. Confirm the four `allowed_flows` (F1–F4) and that the **only** inbound flow to
`sensitive_data` is `F4` from `management`.

### 7 — Validate the firewall rules against the policy

```bash
python3 fw_validate.py --policy segmentation-policy.yaml firewall-rules.csv
```

**Expected:** every rule prints `PASS` **except one FLAG** — the seeded
`tool_sandbox → sensitive_data :5432 ALLOW`, flagged **V1** (no allowed flow; the
protected zone is reachable only via the approved management path). Exit code **1**.

### 8 — Review the flagged rule with the OpenClaw agent

Use **`AI-PROMPTS.md` → "Segmentation review (OpenClaw)"**. The agent must **cite the
policy line** for each denied flow and keep **observations separate from inferences**. It
may only **propose** a fix (remove the rule, or request approval for a new flow) — a
human approves before any inter-zone rule is added.

### 9 — Remediate and re-validate

Remove (or correct) the flagged rule in `firewall-rules.csv`, then re-run Step 7 and
confirm `0 violations`. Do **not** add a path to `sensitive_data` without a recorded
human approval.

### 10 — Run the acceptance check

```bash
python3 verify.py
```

**Expected:** `RESULT: PASS — all Lab 4 checks passed ...`

## Troubleshooting

| Symptom | Fix |
|---|---|
| `python3: command not found` | Use `python` or install Python 3; run from this folder. |
| `FileNotFoundError` on a mock file | Run commands from `labs/lab-04-.../`; check the `mock-data/` path. |
| `--check` reports an OVERLAP | Two CIDRs share addresses — re-carve so each zone starts after the previous broadcast (see the `--need` output). |
| `--check` says `usable=… but … yields …` | The `usable` column must equal `num_addresses − 2` for that prefix (30/14/6/2 for /27–/30). |
| `fw_validate` flags a rule you expected to pass | Read the reason — `V1` = ALLOW of an unlisted flow; `V2` = DENY of a listed flow. Fix the rule or the policy line it cites. |
| The agent proposes opening `sensitive_data` | Reject it. Only the approved `management → sensitive_data` path is allowed, and only with human approval. |

## Acceptance checklist

- [ ] `subnet_plan.py --need` yields `/27,/28,/29,/30` with usable counts **[30, 14, 6, 2]**
- [ ] `subnet_plan.py --check subnets.csv` prints **0 problems** (exit 0) and has **no overlaps**
- [ ] `subnet_plan.py --check mock-data/subnets.bad.csv` **flags the overlap** (exit 1)
- [ ] `fw_validate.py` **flags the seeded** `tool_sandbox → sensitive_data ALLOW` and passes a clean set
- [ ] The OpenClaw review cited policy lines and separated observation from inference
- [ ] No new inter-zone rule was added without a recorded **human approval**
- [ ] `python3 verify.py` prints **PASS**
- [ ] No real IP plans, secrets or personal data appear anywhere in your evidence
