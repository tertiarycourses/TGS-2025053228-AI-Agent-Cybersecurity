# Lab 10 — Capstone: Multi-Agent Cyber-Resilience Improvement Cycle

**Topic 3 · LO3 · Assessment criteria A1, A2, A3**

> Roll up the evidence you produced across **Labs 1–9** into a single
> **cyber-resilience improvement cycle** run by a four-agent team
> (**monitor → triage → responder → improver**). Produce a **resilience maturity
> scorecard**, a **prioritised improvement backlog**, and a **board-ready report** —
> where the improver agent only **proposes** policy changes and a **human approves**
> before the report is finalised.

## Safety boundary

This lab uses **synthetic data only** (`mock-data/sample-evidence/` — a small JSON per
source lab standing in for Labs 1–9). No live systems are touched. Each specialist agent
**cites** the source lab it read, keeps **observation separate from recommendation**, and
uses **only its scoped tools**. The improver agent **proposes**; a **human approves**
before anything would change state. Never paste real secrets, credentials or personal
data into a prompt, a log or `evidence/`.

## What you'll build

- `evidence/scorecard.json` — the resilience maturity scorecard (1–5 per control domain,
  with a target profile) — matches the deck chart
- `evidence/backlog.json` — the prioritised improvement backlog (largest gap first),
  every item traceable to a source lab and to LO1/LO2/LO3
- A board-ready report that records the **human-approval** gate on proposed changes
- A passing `python3 verify.py` acceptance report

## Prerequisites

- Python 3 (standard library only — nothing to install)
- The **Cybersecurity Simulator**: <https://alfredang.github.io/cybersecuritysimulator/>
  (used throughout the course to walk controls per domain)
- The **IP Calculator** and **FauxBank** sample app used across the course (Labs 3–4)
- An OpenClaw workspace and a Hermes Agent workspace (for the orchestration prompts in
  `AI-PROMPTS.md`)
- Ideally, your own `evidence/` from Labs 1–9 (optional — the lab ships synthetic
  roll-ups so it runs standalone)

## Files

| File | Purpose |
|---|---|
| `capstone.py` | Ingest evidence (`--ingest`), score maturity (`--score`), build the backlog (`--backlog`), print the board report (`--report`) |
| `verify.py` | Deterministic acceptance check |
| `mock-data/sample-evidence/lab-01-policy.json` … `lab-09-ir-dr.json` | Synthetic rolled-up inputs standing in for Labs 1–9 (policy findings, IOC counts, crypto flags, subnet check, compliance violations, endpoint posture, log detection, vuln register summary, IR/DR summary) |
| `AI-PROMPTS.md` | Reusable Hermes (multi-agent orchestration) + OpenClaw prompts with the 5 guardrails |
| `evidence/README.md` | What to capture as evidence |

## The six control domains and the roll-up

The capstone aggregates the nine source labs into **six control domains** in this fixed
order — **Policy, Access/Crypto, Network, Monitoring, Response, Recovery** — and derives:

- **current** for a domain = the **minimum** current maturity of its source labs
  (*resilience is only as strong as the weakest evidence in the domain*)
- **target** for a domain = the **maximum** target maturity of its source labs

which reproduces the deck chart exactly:

| Domain | Current | Target | Gap | Source labs |
|---|:--:|:--:|:--:|---|
| Policy | 3 | 4 | 1 | Lab 1 |
| Access/Crypto | 3 | 4 | 1 | Lab 3, Lab 6 |
| Network | 4 | 4 | 0 | Lab 4 |
| Monitoring | 2 | 4 | **2** | Lab 2, Lab 5, Lab 7 |
| Response | 3 | 4 | 1 | Lab 8 |
| Recovery | 2 | 3 | 1 | Lab 9 |

current profile `[3, 3, 4, 2, 3, 2]` → target profile `[4, 4, 4, 4, 4, 3]`.

## Steps

### 1 — Ingest the evidence (the monitor agent)

```bash
python3 capstone.py --ingest evidence/
```

**Expected:** one dataset is built. Because `evidence/` starts empty, the tool
**falls back** to `mock-data/sample-evidence/` and reports `ingested 9 record(s) from
sample-evidence`. Every record carries its **source lab** and **learning outcome**.

### 2 — Walk the domains in the Cybersecurity Simulator

Open <https://alfredang.github.io/cybersecuritysimulator/> and, for each of the six
domains, review **one preventive, one detective and one corrective** control. Note where
your (synthetic) evidence sits below target — this is what the scorecard will quantify.

### 3 — Produce the resilience maturity scorecard (the triage agent)

```bash
python3 capstone.py --score > evidence/scorecard.json
```

**Expected:** the scorecard covers **all six domains** with current profile
`[3, 3, 4, 2, 3, 2]` and target profile `[4, 4, 4, 4, 4, 3]` — matching the deck chart.
Monitoring has the biggest gap (2); Network is already at target (gap 0).

### 4 — Produce the prioritised improvement backlog (the responder agent)

```bash
python3 capstone.py --backlog > evidence/backlog.json
```

**Expected:** the backlog is sorted by **gap descending, then risk**. **Monitoring
(gap 2)** sorts first, then the gap-1 items — the high-risk ones (Access/Crypto,
Response, **Recovery**) before the medium-risk Policy. Every item maps back to its
**source lab(s)** and to **LO1/LO2/LO3**, and carries `requires_human_approval: true`.

### 5 — Draft the board report (the improver agent — propose only)

```bash
python3 capstone.py --report
```

**Expected:** a board-ready summary with the scorecard, the top priorities, and a
**PROPOSED POLICY CHANGES** block. The improver agent **only proposes**: every change is
`PENDING` and the report prints a **HUMAN APPROVAL GATE** stating a human must approve
before the report is finalised.

### 6 — Orchestrate the four-agent team

Use **`AI-PROMPTS.md` → "Multi-agent orchestration (Hermes)"** to run the
monitor → triage → responder → improver chain. Each specialist agent must **cite the
source lab/evidence** for its input, keep **observation separate from recommendation**,
use **only its scoped tools**, and the improver's proposed changes must **wait for human
approval**. Capture the per-agent transcripts.

### 7 — Record the human-approval decision

In `evidence/`, note which proposed changes you **approved or rejected** and why. The
improver agent may **not** apply a change or remove a human-approval gate on its own.

### 8 — Run the acceptance check

```bash
python3 verify.py
```

**Expected:** `RESULT: PASS — scorecard covers 6 domains [3,3,4,2,3,2]->[4,4,4,4,4,3],
backlog is gap-sorted and lab-traceable, and proposed changes require human approval.`

## Troubleshooting

| Symptom | Fix |
|---|---|
| `python3: command not found` | Use `python` or install Python 3; run from this folder. |
| `--ingest` reports `0 record(s)` | Run from `labs/lab-10-.../`; confirm `mock-data/sample-evidence/*.json` exists. |
| Scorecard profile is not `[3,3,4,2,3,2]` | You edited the sample evidence — restore the shipped `mock-data/sample-evidence/` files (current = min, target = max per domain). |
| Backlog order looks wrong | It sorts by **gap desc, then risk** — Monitoring (gap 2) must be P1; check the `gap`/`risk` in your evidence. |
| The agent applies a change itself | Tighten the contract: the improver is **propose-only** and must not remove an approval gate. |

## Acceptance checklist

- [ ] `capstone.py --ingest evidence/` builds one dataset (falls back to sample-evidence)
- [ ] `scorecard.json` covers **all six domains** with current `[3,3,4,2,3,2]` and target `[4,4,4,4,4,3]`
- [ ] `backlog.json` is sorted by **gap descending**; Monitoring (gap 2) is P1; every item is **traceable to a source lab** and to LO1/LO2/LO3
- [ ] `--report` prints the board summary and records that proposed policy changes **require human approval**
- [ ] Per-agent transcripts show each agent **cited its source lab** and separated observation from recommendation
- [ ] `python3 verify.py` prints **PASS** (exit 0)
- [ ] No real secrets or personal data appear anywhere in your evidence
