# Lab 7 — PCAP & Log Investigation

**Topic 2 · LO2 · Assessment criteria A2, K2**

> Read beginner-level packet and log evidence, use an agent to **investigate** a
> firewall log, reconstruct a **timeline** where every claim cites the exact log line,
> separate **observation from inference**, and decide whether to escalate — all
> **propose-only**, with a **human approving** before any detection rule is "deployed".

## Safety boundary

This lab uses **synthetic logs only** (`mock-data/`). No live capture is performed and no
production system is touched. The agent **proposes**; a **human approves** before any
detection rule or block would be applied. Never paste real capture data, IP addresses,
credentials or personal data into a prompt, a log or `evidence/`.

## What you'll build

- A **firewall DENY summary** (by source and by destination port) that matches the
  course chart
- `evidence/timeline.json` — the brute-force timeline (observations = the raw log lines;
  inference = "attempted RDP brute force")
- An **auth confirmation** that segmentation blocked the attacker (no successful login)
- A passing `python3 verify.py` acceptance report

## Prerequisites

- Python 3 (standard library only — nothing to install)
- The **PCAP Analyzer**: <https://alfredang.github.io/pcapanalyzer/>
- An OpenClaw workspace and a Hermes Agent (for the prompts in `AI-PROMPTS.md`)

## Files

| File | Purpose |
|---|---|
| `log_investigate.py` | Summarise the firewall log (`--fw`), detect the brute force (`--detect-bruteforce`), and confirm auth (`--auth`) |
| `verify.py` | Deterministic acceptance check |
| `mock-data/firewall.log` | Synthetic firewall log (`ts action proto src dst sport dport dir`) |
| `mock-data/auth.log` | Synthetic system auth log |
| `AI-PROMPTS.md` | Reusable OpenClaw/Hermes prompts + guardrails |
| `evidence/README.md` | What to capture as evidence |

## Steps

### 1 — Learn to read packet fields in the PCAP Analyzer

Open <https://alfredang.github.io/pcapanalyzer/> and identify, for a few packets, the
**source IP, destination IP, source port, destination port, protocol and timestamp**.
These are the same fields you will read in `mock-data/firewall.log`.

### 2 — Summarise the firewall log

```bash
python3 log_investigate.py --fw mock-data/firewall.log
```

**Expected:** DENY counts **by destination port** of **3389 → 37, 445 → 8, 22 → 5,
443 → 1, 53 → 0** (matching the deck chart), and DENY **by source** showing
`198.51.100.45` as the most-blocked source (37 DENY). Note that **all 37 DENY to
port 3389** come from that **one** source — an **RDP brute-force** signature.

### 3 — Detect the brute force and emit the timeline

```bash
python3 log_investigate.py --detect-bruteforce mock-data/firewall.log > evidence/timeline.json
```

**Expected:** `evidence/timeline.json` with `signature.source = 198.51.100.45`,
`signature.dest_port = 3389`, `signature.service = RDP`, `deny_count = 37`, an
`observations` array holding the **exact log lines**, and
`inference = "attempted RDP brute force …"`. The file is **propose-only**
(`requires_human_approval: true`).

### 4 — Confirm the outcome in the auth log

```bash
python3 log_investigate.py --auth mock-data/auth.log
```

**Expected:** several **failed** attempts from `198.51.100.45` (all
`reason=blocked_by_segmentation`) and **NO successful login** from that IP. Interpretation:
**network segmentation blocked** the RDP brute force at the gateway — the observation and
the inference must stay separate.

### 5 — Investigate with the OpenClaw agent

Use **`AI-PROMPTS.md` → "Firewall investigation (OpenClaw)"**. The agent must **cite the
exact log line** for every claim, keep **observations separate from inferences**, and may
only **propose** a detection rule. It must **not** mark any rule as "deployed".

### 6 — Write the investigation note with Hermes

Use **`AI-PROMPTS.md` → "Investigation note (Hermes)"** to turn the timeline into a short,
cited note (what was observed → what it means → recommended action → escalation decision).
Every line still cites its evidence; the recommendation stays a **proposal**.

### 7 — Record the human-approval decision

In `evidence/`, record which proposed detection rule you **approved or rejected** and why.
No rule is "deployed" until a human approves it. The agent may **not** approve its own
proposal.

### 8 — Run the acceptance check

```bash
python3 verify.py
```

**Expected:** `RESULT: PASS — all Lab 7 checks passed …`

## Troubleshooting

| Symptom | Fix |
|---|---|
| `python3: command not found` | Use `python` or install Python 3; run from this folder. |
| `FileNotFoundError` on a mock file | Run commands from `labs/lab-07-.../`; check the `mock-data/` path. |
| `timeline.json` is empty / `detected: false` | You redirected the wrong command — use `--detect-bruteforce mock-data/firewall.log`. Do not edit `firewall.log`. |
| `--detect-bruteforce` prints extra text into the JSON | Only the JSON is printed on stdout; make sure you did not add prints. Re-run the exact command. |
| The agent invents an IP or a log line | Tighten the prompt contract — every claim must quote an existing `firewall.log` line verbatim; it may not fabricate. |

## Acceptance checklist

- [ ] `--fw` DENY-by-port equals **3389=37, 445=8, 22=5, 443=1, 53=0** (matches the chart)
- [ ] `evidence/timeline.json` names the brute force as **198.51.100.45 → 3389 (RDP)** with **37** observations
- [ ] Every timeline observation **cites a real `firewall.log` line**; observation is kept separate from inference
- [ ] `--auth` confirms **no successful login** from `198.51.100.45` (segmentation blocked it)
- [ ] The OpenClaw/Hermes work cited log lines and stayed **propose-only** (a human approved before any rule was "deployed")
- [ ] `python3 verify.py` prints **PASS**
- [ ] No real capture data, IP addresses or personal data appear anywhere in your evidence
