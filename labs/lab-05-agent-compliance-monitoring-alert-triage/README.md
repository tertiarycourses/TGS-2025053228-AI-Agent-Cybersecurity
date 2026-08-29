# Lab 5 — Agent Compliance Monitoring & Alert Triage

**Topic 2 · LO2 · Assessment criteria A2, K1**

> Monitor a logged AI-agent action stream against a **machine-checkable** policy,
> flag every **compliance violation**, and run a **severity × confidence** triage that
> turns findings into a prioritised alert queue — keeping **observation** separate from
> **inference** and holding every high-risk action for **human approval**.

## Safety boundary

This lab uses **synthetic data only** (`mock-data/`). No live systems are touched.
The agent **proposes**; a **human approves** before any containment would change state.
Every alert must **cite the exact audit line** it came from — the triage never fabricates
a log entry. Never paste real secrets, credentials or personal data into a prompt, a log
or `evidence/`.

## What you'll build

- `mock-data/policy.yaml` — the agent policy (allowed tools per agent, which assets need
  approval, which data is Confidential)
- `evidence/compliance-report.json` — the flagged findings, graded by severity
- `evidence/alert-queue.json` — the prioritised alert queue (observation vs inference,
  each alert citing its audit line)
- A passing `python3 verify.py` acceptance report

## Prerequisites

- Python 3 (standard library only — nothing to install)
- The **Cybersecurity Simulator**: <https://alfredang.github.io/cybersecuritysimulator/>
- A **Hermes Agent** workspace (for the alert-triage prompt in `AI-PROMPTS.md`)
- An **OpenClaw** workspace (for the report-review prompt in `AI-PROMPTS.md`)

## Files

| File | Purpose |
|---|---|
| `compliance_check.py` | Analyse the audit stream vs the policy (`--policy … --audit …`); re-print a saved report (`--report …`) |
| `triage.py` | Score findings (severity × confidence) and emit the alert queue |
| `miniyaml.py` | Tiny standard-library YAML-subset loader (no third-party deps) |
| `verify.py` | Deterministic acceptance check |
| `mock-data/policy.yaml` | The agent policy (agents + allowed tools, assets + classification/approval) |
| `mock-data/agent-audit.jsonl` | The seeded audit log — one logged agent action per line |
| `AI-PROMPTS.md` | Reusable Hermes/OpenClaw prompts + guardrails |
| `evidence/README.md` | What to capture as evidence |

## Steps

### 1 — Read the policy and the audit log

Open `mock-data/policy.yaml`. Each **agent** has an `allowed_tools` list; each **asset**
has a `classification`, whether it is `state_changing`, and whether `human_approval` is
`required`. Then open `mock-data/agent-audit.jsonl`: **one JSON object per line** is a
logged agent action `{ts, agent, tool, target, approved, classification, control}`.

**Expected:** 35 logged actions; 2 agents (`hermes`, `openclaw`); the Confidential assets
are `learner_records`, `admin_account`, `agent_memory_store`, `payment_tokens`.

### 2 — Map the control categories in the Cybersecurity Simulator

Open <https://alfredang.github.io/cybersecuritysimulator/> and walk **one detective and
one corrective** control for each category (access, cryptography, operations, incident).
Compliance monitoring is a **detective** control; the human-approved containment you queue
in Step 5 is a **corrective** one. Note which category each maps to.

### 3 — Run the compliance check against the audit stream

```bash
python3 compliance_check.py --policy mock-data/policy.yaml --audit mock-data/agent-audit.jsonl
```

**Expected:** `35 actions analysed`, `7 violations flagged (2 CRITICAL)`, and the
by-severity line `Critical=2, High=5, Medium=9, Low=12, Info=7`. The check flags an action
when it (a) uses a tool **outside** the agent's allow-list, (b) **skips a required
approval** on a state-changing action, or (c) touches **Confidential** data **without a
control**. The report is written to `evidence/compliance-report.json`.

### 4 — Re-read the saved report

```bash
python3 compliance_check.py --report evidence/compliance-report.json
```

**Expected:** the same summary, printed from the saved JSON. Confirm the **two CRITICAL
findings** cite **line 1** (missing approval on `payment_tokens`) and **line 3**
(`hermes` used the out-of-scope tool `write_ticket`).

### 5 — Triage the findings into an alert queue

```bash
python3 triage.py evidence/compliance-report.json > evidence/alert-queue.json
```

**Expected:** an alert queue of **35 alerts**, ordered highest-risk first, with
`by_severity` `Critical=2, High=5, Medium=9, Low=12, Info=7`. Open the JSON: every alert
keeps `observation` (what the log line shows) **separate** from `inference` (the
`SUSPECTED` cause), cites its `audit_line`, sets `auto_contained: false`, and marks every
Critical/High alert `requires_human_approval: true`.

### 6 — Review the alert queue with the Hermes Agent

Use **`AI-PROMPTS.md` → "Alert triage (Hermes)"**. The agent must **cite the audit line**
for every alert, **separate observation from inference**, and **never fabricate** a log
entry. It may only **propose** containment — a human approves first.

### 7 — Record the human-approval decision

For each **Critical** alert, write a one-line decision (approve / reject containment and
why) in `evidence/` (see `evidence/README.md`). The agent may **not** contain anything
without this record.

### 8 — Run the acceptance check

```bash
python3 verify.py
```

**Expected:** per-check `PASS` lines, then
`RESULT: PASS — 2 seeded criticals detected, 0 false positives, severity counts
[2,5,9,12,7], every alert cites a real audit line.`

## Troubleshooting

| Symptom | Fix |
|---|---|
| `python3: command not found` | Use `python` or install Python 3; run from this folder. |
| `FileNotFoundError` on a mock file | Run commands from `labs/lab-05-.../`; check the `mock-data/` path. |
| `alert-queue.json` is empty | Run Step 3 **before** Step 5 — triage reads the report Step 3 writes. |
| Counts are not `[2,5,9,12,7]` | You edited the seeded audit log; restore `mock-data/agent-audit.jsonl`. |
| An alert has no `audit_line` | Don't hand-edit the queue — regenerate it with `triage.py`; every alert must cite a line. |
| The agent invents a log entry | Tighten the prompt contract; it must cite an existing `audit_line` and may not fabricate. |

## Acceptance checklist

- [ ] `compliance_check.py --policy … --audit …` flags **7 violations, 2 CRITICAL**
- [ ] The two criticals are the **out-of-scope tool** (line 3) and the **missing approval** (line 1)
- [ ] `triage.py` emits **35 alerts** with by-severity **Critical=2, High=5, Medium=9, Low=12, Info=7**
- [ ] Every alert **cites its audit line** and keeps **observation separate from inference**
- [ ] No containment is auto-applied; every Critical/High alert is **held for human approval**
- [ ] `python3 verify.py` prints **RESULT: PASS**
- [ ] No real secrets or personal data appear anywhere in your evidence
