# Lab 6 — Endpoint Hardening & Controlled Validation

**Topic 2 · LO2 · Assessment criteria K2, A2**

> Score a synthetic BYOD / remote-work endpoint fleet against a **machine-checkable
> hardening baseline** (patching, host firewall, disk encryption, MFA-for-RDP,
> application allow-listing), find the **weakest controls**, and drive an AI agent
> to draft a **propose-only** remediation plan — validating any live check ONLY
> against the authorized Ethical Hacking Trainer target.

## Safety boundary

This lab uses **synthetic data only** (`mock-data/endpoints.csv`) plus, for the optional
live walkthrough, the **authorized Ethical Hacking Trainer**:
<https://alfredang.github.io/ethnicalhacking/>. You may run **only the read-only checks
this lab lists** against that authorized target — **never** a real, production or
internet host, and **no exploitation**. The agent **proposes**; a **human approves**
before any hardening would change state. Never paste real secrets, credentials or
personal data into a prompt, a log or `evidence/`.

## What you'll build

- `baseline.yaml` — the endpoint hardening baseline (5 required K2 controls)
- `evidence/posture.json` — the scored fleet posture (per-control pass rate + weakest controls)
- A **propose-only** remediation plan for the two weakest controls (needs human approval)
- A passing `python3 verify.py` acceptance report

## Prerequisites

- Python 3 (standard library only — nothing to install)
- The **Ethical Hacking Trainer** (authorized target): <https://alfredang.github.io/ethnicalhacking/>
- An OpenClaw workspace (for the remediation prompt in `AI-PROMPTS.md`)
- A Hermes Agent workspace (for the posture sanity-check prompt)

## Files

| File | Purpose |
|---|---|
| `harden_check.py` | Print the inventory (`--inventory`) and score it against a baseline (`--score`) |
| `miniyaml.py` | Tiny standard-library YAML-subset loader (no third-party deps) |
| `verify.py` | Deterministic acceptance check |
| `mock-data/endpoints.csv` | The synthetic 100-endpoint fleet (per-control pass/fail) |
| `mock-data/baseline.starter.yaml` | A compliant baseline you copy to `baseline.yaml` |
| `AI-PROMPTS.md` | Reusable OpenClaw/Hermes prompts + guardrails |
| `evidence/README.md` | What to capture as evidence |

## Steps

### 1 — Review the synthetic endpoint fleet

```bash
python3 harden_check.py --inventory mock-data/endpoints.csv
```

**Expected:** a table of **100 endpoints** (`BYOD-001 … BYOD-100`), each with a
`pass`/`fail` cell for the five controls, ending in
`100 endpoints in the synthetic inventory (read-only)`. Nothing is scanned; this reads
the CSV only.

### 2 — Copy the hardening baseline

```bash
cp mock-data/baseline.starter.yaml baseline.yaml
```

Open `baseline.yaml`. Confirm all **five K2 controls** are present and each sets
`required: true`: `patching`, `host_firewall`, `disk_encryption`, `mfa_rdp`,
`app_allowlist`. Each control also records the **BYOD/remote-work risk** it mitigates.

### 3 — Score the fleet against the baseline

```bash
python3 harden_check.py --score baseline.yaml mock-data/endpoints.csv
```

**Expected:** the per-control **PASS RATE** matches the deck chart —
`patching 72%`, `host_firewall 65%`, `disk_encryption 88%`, `mfa_rdp 54%`,
`app_allowlist 41%` — an overall **fleet posture of 64%**, and the **weakest controls**
listed as **`mfa_rdp` and `app_allowlist`**. Add `--json` to emit the posture model:

```bash
python3 harden_check.py --score baseline.yaml mock-data/endpoints.csv --json > evidence/posture.json
```

### 4 — (Optional) Controlled validation on the authorized target

Open **only** <https://alfredang.github.io/ethnicalhacking/> and walk the **read-only**
hardening checks it exposes (is a host firewall on? is the disk encrypted? is MFA
enforced for remote access?). This is a **controlled, authorized** validation:
observe and record — **do not exploit**, and **do not point any check at a real or
internet host**.

### 5 — Draft the remediation plan with the OpenClaw agent

Use **`AI-PROMPTS.md` → "Hardening remediation (OpenClaw)"**. Paste the `--score`
output (or `posture.json`). The agent must **cite the failing check**, map each to a
**BYOD/remote-work risk**, and mark **every 'apply hardening' change as requiring HUMAN
APPROVAL** (propose-only). It focuses on the two weakest controls first.

### 6 — Sanity-check the posture with the Hermes agent

Use **`AI-PROMPTS.md` → "Posture sanity-check (Hermes)"** to confirm the reported pass
rates and the weakest-control call are internally consistent, and that no proposed
change was applied. The agent cites the JSON path for every claim.

### 7 — Record the human-approval decision

Write a short note (see `evidence/`) of which proposed hardening change you
**approved / rejected** and why. **Nothing** is applied by the agent; approval is the
gate.

### 8 — Run the acceptance check

```bash
python3 verify.py
```

**Expected:** `RESULT: PASS — all Lab 6 checks passed.`

## Troubleshooting

| Symptom | Fix |
|---|---|
| `python3: command not found` | Use `python` or install Python 3; run from this folder. |
| `FileNotFoundError` on a mock file | Run commands from `labs/lab-06-.../`; check the `mock-data/` path. |
| Pass rates are not 72/65/88/54/41 | You edited `endpoints.csv`; restore it — the fleet is seeded to the deck chart. |
| `--score` shows a different weakest pair | Confirm all 5 controls are `required: true` in `baseline.yaml`. |
| The agent proposes auto-applying a fix | Tighten the contract: every change is propose-only and needs human approval. |
| The agent wants to scan a real host | Refuse. Validation is read-only and only against the authorized trainer target. |

## Acceptance checklist

- [ ] `harden_check.py --inventory …` lists **100 endpoints**
- [ ] `harden_check.py --score …` reports **72 / 65 / 88 / 54 / 41** and weakest = **mfa_rdp, app_allowlist**
- [ ] `baseline.yaml` covers all **5 K2 controls**, each `required: true`
- [ ] The OpenClaw remediation plan **cited each failing check**, mapped it to a BYOD/remote risk, and marked every change **HUMAN APPROVAL required**
- [ ] Any live validation stayed on the **authorized trainer target** and used **read-only** checks only (no exploitation)
- [ ] A **human-approval record** shows what you approved/rejected
- [ ] `python3 verify.py` prints **PASS**
- [ ] No real secrets or personal data appear anywhere in your evidence
