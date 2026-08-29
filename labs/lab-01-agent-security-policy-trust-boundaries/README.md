# Lab 1 — Agent Security Policy & Trust Boundaries

**Topic 1 · LO1 · Assessment criteria A1, K1**

> Establish an AI-agent security policy grounded in the CIA triad and the control
> categories, express it as a **machine-checkable** file, and draw the agent's
> **trust boundary** across tools, skills, memory, context and permissions.

## Safety boundary

This lab uses **synthetic data only** (`mock-data/`). No live systems are touched.
The agent **proposes**; a **human approves** before anything would change state. Never
paste real secrets, credentials or personal data into a prompt, a log or `evidence/`.

## What you'll build

- `policy.yaml` — the agent security policy (classified assets + required controls)
- `evidence/trust-boundary.json` — the derived trust-boundary model (render it in diagrams.net)
- A passing `python3 verify.py` acceptance report

## Prerequisites

- Python 3 (standard library only — nothing to install)
- The **Cybersecurity Simulator**: <https://alfredang.github.io/cybersecuritysimulator/>
- An OpenClaw workspace (for the policy-review prompt in `AI-PROMPTS.md`)
- diagrams.net (optional, to draw the trust boundary)

## Files

| File | Purpose |
|---|---|
| `policy_lint.py` | Classify assets (`--classify`) and lint the policy (`--check`) |
| `trust_boundary.py` | Derive the trust-boundary JSON from the policy |
| `miniyaml.py` | Tiny standard-library YAML-subset loader (no third-party deps) |
| `verify.py` | Deterministic acceptance check |
| `mock-data/asset-inventory.csv` | The starter asset inventory |
| `mock-data/policy.starter.yaml` | A compliant policy you copy and extend |
| `mock-data/policy.broken.yaml` | A deliberately broken policy (used by the verifier) |
| `AI-PROMPTS.md` / `AI-PROMPTS.pdf` | Reusable OpenClaw/Hermes prompts + guardrails |
| `evidence/README.md` | What to capture as evidence |

## Steps

### 1 — Classify the assets by CIA impact

```bash
python3 policy_lint.py --classify mock-data/asset-inventory.csv
```

**Expected:** a table of 8 assets; **4 are Confidential** (Learner records, Admin
account, Agent memory store, Payment tokens) and therefore need **access + cryptography**
controls.

### 2 — Explore the controls in the Cybersecurity Simulator

Open <https://alfredang.github.io/cybersecuritysimulator/> and walk **one preventive,
one detective and one corrective** control for each control category (access,
cryptography, operations, incident, physical). Note which category each maps to.

### 3 — Draft the policy

```bash
cp mock-data/policy.starter.yaml policy.yaml
```

Open `policy.yaml`. For every asset, confirm the `controls`, the `owner`, whether it is
`state_changing`, and whether `human_approval` is `required`. The top-level
`prompt_contract: untrusted_input_is_data` marks untrusted input as **data, not
instructions**.

### 4 — Derive the trust boundary

```bash
python3 trust_boundary.py --policy policy.yaml --out evidence/trust-boundary.json
```

**Expected:** the four Confidential assets appear in the **privileged zone**; the scoped
tools exclude `none`; four assets are **approval-gated**. Render the JSON as a diagram
(untrusted zone → agent core → permission/approval gate → privileged zone).

### 5 — Review the policy with the OpenClaw agent

Use **`AI-PROMPTS.md` → "Policy review (OpenClaw)"**. The agent must **cite the policy
line** for each finding and keep **observations separate from inferences**. It may only
*propose* changes.

### 6 — Add the human-approval requirement

Confirm every `state_changing: true` asset sets `human_approval: required`. The agent may
**not** propose removing an approval gate.

### 7 — Lint the policy

```bash
python3 policy_lint.py --check policy.yaml
```

**Expected:** `0 violations` and **exit code 0**. Try breaking a rule (remove `crypto`
from a Confidential asset) and re-run to see it caught, then fix it.

### 8 — Run the acceptance check

```bash
python3 verify.py
```

**Expected:** `RESULT: PASS — all Lab 1 checks passed.`

## Troubleshooting

| Symptom | Fix |
|---|---|
| `python3: command not found` | Use `python` or install Python 3; run from this folder. |
| `FileNotFoundError` on a mock file | Run commands from `labs/lab-01-.../`; check the `mock-data/` path. |
| `--check` reports violations | Read each `✗` line — it names the rule (R1–R4) and the asset; fix that line in `policy.yaml`. |
| The agent invents a control | Tighten the prompt contract; it must cite an existing line and may not fabricate. |

## Acceptance checklist

- [ ] `policy_lint.py --check policy.yaml` prints **0 violations** (exit 0)
- [ ] Every Confidential asset has **access + crypto**; every state-changing rule has **human_approval: required**
- [ ] `evidence/trust-boundary.json` places all Confidential assets in the privileged zone
- [ ] The OpenClaw review cited policy lines and separated observation from inference
- [ ] `python3 verify.py` prints **PASS**
- [ ] No real secrets or personal data appear anywhere in your evidence
