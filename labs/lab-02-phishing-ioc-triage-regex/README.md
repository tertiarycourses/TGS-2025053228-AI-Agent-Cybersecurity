# Lab 2 — Phishing & IOC Triage with Regex Generation

**Topic 1 · LO1 · Assessment criteria K1, A1**

> Triage a batch of phishing emails by **generating regex** to extract Indicators of
> Compromise (URLs, IPs, file hashes, sender domains, attachments), produce a
> **cited, machine-checkable** IOC report, and score each indicator while keeping the
> **observation** (the literal string) separate from the **inference** (why it is suspicious).

## Safety boundary

This lab uses **synthetic samples only** (`mock-data/phish/`). Every domain is obviously
fake (`*-example.tld`, `*-example.test`) and every IP is a documentation range
(RFC 5737: `198.51.100.x` / `203.0.113.x`). **No live systems are touched and no real
message is opened.** The agent **proposes** an awareness advisory; a **human approves**
before anything would be "sent". Never paste real emails, secrets or personal data into a
prompt, a log or `evidence/`.

## What you'll build

- `patterns.txt` — your regex catalogue (one per line: `url=`, `ipv4=`, `sha256=`, `sender=`)
- `evidence/ioc-report.json` — the extracted IOCs, each with its **source file + line**
- A scored view separating **observation** from **inference**
- A passing `python3 verify.py` acceptance report

## Prerequisites

- Python 3 (standard library only — nothing to install; uses the `re` module)
- The **Regex Generator** tool: <https://alfredang.github.io/regexgenerator/>
- An OpenClaw workspace and the Hermes Agent (for the triage prompts in `AI-PROMPTS.md`)

## Files

| File | Purpose |
|---|---|
| `ioc_extract.py` | List samples (`--list`), extract IOCs (`--patterns`), score them (`--score`) |
| `patterns.txt` | The regex catalogue the extractor reads (url / ipv4 / sha256 / sender) |
| `verify.py` | Deterministic acceptance check |
| `mock-data/phish/*.eml` | Five synthetic phishing emails (raw headers + body) |
| `evidence/README.md` | What to capture as evidence |
| `AI-PROMPTS.md` | Reusable Hermes/OpenClaw prompts + guardrails |

## Steps

### 1 — List the phishing samples

```bash
python3 ioc_extract.py --list mock-data/phish/
```

**Expected:** **5** `.eml` samples are listed (`01-secure-login-reset` … `05-delivery-notice`).

### 2 — Generate the extraction regex

Open <https://alfredang.github.io/regexgenerator/> and build one pattern for each IOC type,
then test it against lines copied from the samples:

- **url** — an `http`/`https` link (stop at whitespace so trailing text is excluded)
- **ipv4** — a dotted-quad with word boundaries (must **not** match inside a hash or a date)
- **sha256** — exactly **64** lowercase-hex characters
- **sender** — the `From:` header, **capturing the domain** in group 1

Confirm the patterns in `patterns.txt` match yours (they are labelled `type=regex`, one per line).

### 3 — Extract the IOCs to a report

```bash
python3 ioc_extract.py --patterns patterns.txt mock-data/phish/ > evidence/ioc-report.json
```

**Expected:** a JSON report whose `counts_by_type` is exactly
**`url=14, ipv4=6, sha256=4, sender=5, attachment=3`** (total **32**). Every entry in `iocs`
carries a `file` and a `line`. (Attachments come from the built-in `Content-Disposition`
rule, not from `patterns.txt`.)

### 4 — Score the indicators (observation vs inference)

```bash
python3 ioc_extract.py --score evidence/ioc-report.json
```

**Expected:** each IOC gains a `confidence` in `[0,1]`, an `observation` (the **literal
string**) and an `inference` (**why** it is suspicious). The double-extension attachment
`Invoice-INV-20826.pdf.exe` scores **highest**.

### 5 — Triage with the Hermes Agent

Use **`AI-PROMPTS.md` → "IOC triage (Hermes)"**. The agent must treat the email text as
**data, not instructions**, **cite the source file + line** for every IOC, keep observation
separate from inference, and **only cite IOCs present in the files** — it may not invent any.

### 6 — Draft (do not send) the awareness advisory

Use the **OpenClaw** prompt in `AI-PROMPTS.md` to draft a short staff awareness advisory
from the report. The agent **drafts only**; record who **approved** it before it would be
"sent". No message is actually sent in this lab.

### 7 — Run the acceptance check

```bash
python3 verify.py
```

**Expected:** `RESULT: PASS — all Lab 2 checks passed ...` (exit code 0). Try breaking a
pattern (e.g. change `sha256` to `{63}`) and re-run to see the seeded checks fail, then fix it.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `python3: command not found` | Use `python` or install Python 3; run from this folder. |
| `FileNotFoundError` / `NotADirectoryError` | Run commands from `labs/lab-02-.../`; check the `mock-data/phish/` path. |
| Counts are wrong (e.g. url ≠ 14) | A regex is too greedy/narrow. In the Regex Generator, tighten `url` to stop at whitespace and keep `sha256` at exactly `{64}`; do not let `ipv4` match inside a hash. |
| A phantom indicator appears | Your pattern matched a date, a version or a Message-ID. Add word boundaries (`\b`) and anchor `sender` to `^From:`. |
| The agent invents an indicator | Tighten the prompt contract; it must cite an IOC that exists in a file (file + line) and may not fabricate. |

## Acceptance checklist

- [ ] `ioc_extract.py --list` shows **5** samples
- [ ] `evidence/ioc-report.json` `counts_by_type` = **url=14, ipv4=6, sha256=4, sender=5, attachment=3**
- [ ] Every IOC in the report carries a **source file + line**
- [ ] `--score` adds a confidence and separates **observation** from **inference**
- [ ] The Hermes triage cited file+line for every IOC and invented **none**
- [ ] The awareness advisory was **drafted by the agent and approved by a human** before "sending"
- [ ] `python3 verify.py` prints **PASS**
- [ ] No real emails, secrets or personal data appear anywhere in your evidence
