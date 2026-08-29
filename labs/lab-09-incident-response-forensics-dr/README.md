# Lab 9 — Incident Response, Forensics & DR with Human Approvals

**Topic 3 · LO3 · Assessment criteria A3, A2**

> Work a synthetic **agent data-exfiltration** incident end to end: build an
> **incident-response timeline** across the six IR phases, **preserve forensic
> artifacts** with a chain-of-custody log, and derive a **disaster-recovery plan**
> (backup frequency + restore order) — with every state-changing step **gated behind
> human approval**.

## Safety boundary

This lab uses a **synthetic incident** and **synthetic data only** (`mock-data/`). No
live systems are touched, no host is really isolated, no credential is really rotated,
no backup is really restored. The agent **proposes**; a **human approves** before
anything would change state. Never paste real secrets, credentials, host names or
personal data into a prompt, a log or `evidence/`.

## What you'll build

- `evidence/timeline.json` — the ordered IR timeline (six phases, observation vs inference)
- `evidence/custody.csv` — the chain-of-custody log (SHA-256 per preserved artifact)
- `evidence/recovery-plan.json` — the DR plan (backup frequency + RTO-ascending restore order)
- A passing `python3 verify.py` acceptance report

## Prerequisites

- Python 3 (standard library only — nothing to install)
- The **Cybersecurity Simulator**: <https://alfredang.github.io/cybersecuritysimulator/>
- A Hermes Agent workspace and an OpenClaw workspace (for the prompts in `AI-PROMPTS.md`)

## Files

| File | Purpose |
|---|---|
| `ir_timeline.py` | Order incident events by IR phase + time; separate observation from inference |
| `forensics.py` | Hash each artifact (SHA-256) and write the chain-of-custody log (`--preserve`) |
| `dr_plan.py` | Derive backup frequency (from RPO) and restore order (RTO ascending) |
| `verify.py` | Deterministic acceptance check |
| `mock-data/incident-events.jsonl` | The synthetic incident — one JSON event per line, tagged with an IR phase |
| `mock-data/artifacts/` | Small synthetic artifacts to preserve (`memory-note.txt`, `suspicious.log`, `export.csv`) |
| `mock-data/systems.csv` | Systems inventory with RTO/RPO/criticality (seeded to match the deck chart) |
| `AI-PROMPTS.md` | Reusable Hermes/OpenClaw prompts + guardrails |
| `evidence/README.md` | What to capture as evidence |

## Steps

### 1 — Build the incident-response timeline

```bash
python3 ir_timeline.py mock-data/incident-events.jsonl > evidence/timeline.json
```

**Expected:** `evidence/timeline.json` with `all_phases_present: true` and all **six IR
phases in order** — `prepare → detect → contain → eradicate → recover → learn` — and
each entry keeping **observation** (event facts) separate from **inference** (attacker
action). Read it top to bottom: it is the exfiltration story, from the injected memory
note to the post-incident lessons.

### 2 — Walk the IR phases in the Cybersecurity Simulator

Open <https://alfredang.github.io/cybersecuritysimulator/> and step through one action
per phase (prepare, detect, contain, eradicate, recover, learn). Note which of the
containment/recovery actions **change state** and therefore need a human-approval gate.

### 3 — Preserve the forensic artifacts (chain of custody)

```bash
python3 forensics.py --preserve mock-data/artifacts/ --log evidence/custody.csv
```

**Expected:** `evidence/custody.csv` with a row per artifact —
`artifact, sha256, size, preserved_at, handler`. Note the full 64-hex SHA-256 for each
file; this is what proves integrity later.

### 4 — Prove the custody hashes are reproducible

```bash
python3 forensics.py --preserve mock-data/artifacts/ --log evidence/custody.csv
```

**Expected:** re-running reproduces **identical** hashes (the artifacts are unchanged),
so the chain of custody holds. Try changing one byte of `mock-data/artifacts/export.csv`,
re-run, and watch that file's digest change — then restore the byte and confirm it returns.

### 5 — Derive the disaster-recovery plan

```bash
python3 dr_plan.py --systems mock-data/systems.csv > evidence/recovery-plan.json
```

**Expected:** `restore_order` = **Payments API → Agent runtime → Customer DB →
Internal wiki → Reporting** with RTOs **[2, 4, 6, 24, 48]** (RTO ascending). Each system
also carries a `backup_frequency` derived from its RPO (back up at least once per RPO
window).

### 6 — Draft the agent IR plan with citations + approval gates

Use **`AI-PROMPTS.md` → "IR plan (Hermes)"**. The agent must **cite the timeline entry**
(`seq`/`phase`) behind each step, keep **observation separate from inference**, and
**GATE every state-changing step** (isolate host, rotate credentials, restore backup)
behind an explicit **HUMAN APPROVAL** — it may only *propose*.

### 7 — Review the forensic evidence with the OpenClaw agent

Use **`AI-PROMPTS.md` → "Forensic evidence review (OpenClaw)"**. The agent cites the
custody row (artifact + sha256) for each finding, separates observation from inference,
and may only *propose* — it must never suggest altering an artifact or a hash.

### 8 — Run the acceptance check

```bash
python3 verify.py
```

**Expected:** `RESULT: PASS — ...` and **exit code 0**.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `python3: command not found` | Use `python` or install Python 3; run from this folder. |
| `FileNotFoundError` on a mock file | Run commands from `labs/lab-09-.../`; check the `mock-data/` path. |
| `No such file or directory: 'evidence/...'` | The scripts create `evidence/` on write; run from the lab folder so the relative path resolves. |
| A custody hash changed unexpectedly | An artifact's bytes changed — that's the point of the hash. Restore the original file. |
| `verify.py` FAILs on the timeline | An event's `phase` is misspelled or missing; it must be one of prepare/detect/contain/eradicate/recover/learn. |
| `verify.py` FAILs on restore order | Keep the seeded RTOs in `systems.csv` (2, 4, 6, 24, 48); the order is derived by sorting RTO ascending. |

## Acceptance checklist

- [ ] `evidence/timeline.json` has all **six IR phases in order**, observation separate from inference
- [ ] `evidence/custody.csv` has a SHA-256 per artifact and **re-running reproduces identical hashes**
- [ ] `evidence/recovery-plan.json` restore order is **[Payments API, Agent runtime, Customer DB, Internal wiki, Reporting]** with RTOs **[2,4,6,24,48]**
- [ ] The Hermes IR plan **cited timeline entries**, separated observation from inference, and **gated every state-changing step** behind human approval
- [ ] The OpenClaw forensic review cited custody rows and separated observation from inference
- [ ] `python3 verify.py` prints **RESULT: PASS** (exit 0)
- [ ] No real secrets, host names or personal data appear anywhere in your evidence
