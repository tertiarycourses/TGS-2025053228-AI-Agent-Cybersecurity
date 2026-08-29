# Lab 3 — Identity, Secrets, Encryption & Crypto Validation

**Topic 1 · LO1 · Assessment criteria A1, K1**

> Find hard-coded **secrets** in an agent's configuration, decide correctly when to
> **hash** versus **encrypt** each kind of data, score password **entropy** against a
> policy floor, and **validate a certificate** — flagging an expired one — using only
> the Python standard library.

## Safety boundary

This lab uses **synthetic data only** (`mock-data/`). Every secret, password and
certificate here is **fake** and planted for the exercise. No live systems are touched.
The agent **proposes** (e.g. "rotate this key", "reissue this cert"); a **human approves**
before anything would change state. **Never** paste real secrets, credentials or personal
data into a prompt, a log or `evidence/`, and never print a secret value back out.

## What you'll build

- A **redacted secret-scan report** for `mock-data/agent-config/` (file + line, no values)
- A **hash-vs-encrypt** decision table for the data inventory
- A **password entropy** report flagging weak credentials
- A **certificate validation** result that detects an **expired** cert
- A passing `python3 verify.py` acceptance report

## Prerequisites

- Python 3 (standard library only — nothing to install; uses `hashlib`, `secrets`, `math`, `ssl`)
- The **Cryptography Toolkit**: <https://alfredang.github.io/cryptography-toolkit/>
- An OpenClaw workspace (for the secrets-review prompt in `AI-PROMPTS.md`)
- `openssl` on the path (only if you want to regenerate the sample certificate)

## Files

| File | Purpose |
|---|---|
| `secret_scan.py` | Recursively scan a directory for hard-coded secrets; report file + line, **redacted** |
| `crypto_check.py` | `--classify` (hash vs encrypt), `--entropy` (password strength), `--cert` (validate/expiry) |
| `verify.py` | Deterministic acceptance check |
| `mock-data/agent-config/` | Seeded config (`config.yaml`, `.env.sample`, `settings.json`) with **5 planted secrets** |
| `mock-data/data-items.csv` | Data inventory (`item,type`) for the hash-vs-encrypt decision |
| `mock-data/creds-sample.txt` | Four sample passwords across strength tiers |
| `mock-data/agent-cert.pem` | An **already-expired** self-signed certificate |
| `mock-data/agent-cert.meta` | Explicit `notAfter` used to keep the expiry check deterministic |
| `AI-PROMPTS.md` | Reusable OpenClaw/Hermes prompts + guardrails |
| `evidence/README.md` | What to capture as evidence |

## Steps

### 1 — Scan the agent config for hard-coded secrets

```bash
python3 secret_scan.py mock-data/agent-config/
```

**Expected:** **5 findings** across 3 files — a cloud access key id and a Slack token in
`config.yaml`, a database password in `.env.sample`, and an API key and a private-key
block in `settings.json`. Each line shows the **file, line number and kind** with the
value **redacted** (e.g. `AK…[redacted, 20 chars]`). The report never prints a secret.

### 2 — Explore hashing vs encryption in the Cryptography Toolkit

Open <https://alfredang.github.io/cryptography-toolkit/> and try a **one-way hash**
(SHA-256) and a **reversible cipher**. Note the rule of thumb: if you only ever need to
**verify** a value (passwords, integrity checks) you **hash**; if you must **read it back**
(PII, secrets, confidential data) you **encrypt** and manage the key.

### 3 — Classify each data item as HASH or ENCRYPT

```bash
python3 crypto_check.py --classify mock-data/data-items.csv
```

**Expected:** **4 items HASH** (the two passwords + the two integrity digests) and
**7 items ENCRYPT** (PII, the confidential card number, and the three secrets/tokens);
the public marketing slogan needs **NEITHER**. Each row states the reason.

### 4 — Score password entropy against the policy floor

```bash
python3 crypto_check.py --entropy mock-data/creds-sample.txt
```

**Expected:** four passwords with **strictly increasing** entropy — an 8-char lowercase
(~37.6 bits), an 8-char mixed (~47.6 bits), a 12-char mixed (~78.8 bits) and a 16-char
passphrase (~97.7 bits). The two weakest are **flagged WEAK** because they fall below the
**60-bit** policy floor. Passwords are shown redacted. (The deck's illustrative
"crack cost by tier" `[1, 30, 9000, 500000]` is just the intuition — what matters is that
the four tiers' entropy **increases**.)

### 5 — Validate the agent certificate

```bash
python3 crypto_check.py --cert mock-data/agent-cert.pem
```

**Expected:** the subject/issuer (`CN=agent.local`), the validity window, a **2048-bit
RSA** key size, and **STATUS: EXPIRED** — because `notAfter` (2020-03-01) is in the past.
The tool **proposes** renew/reissue and notes that **revoke needs human approval**.

### 6 — Review the config with the OpenClaw agent

Use **`AI-PROMPTS.md` → "Secrets review (OpenClaw)"**. The agent must **cite file + line**
for every finding, **must not echo any secret value**, and may only **propose** a fix.
Any `rotate key` / `revoke cert` action is **propose-only** and requires **human approval**.

### 7 — Run the acceptance check

```bash
python3 verify.py
```

**Expected:** `RESULT: PASS — all Lab 3 checks passed ...` (exit code 0). It asserts the
scanner finds **exactly the 5** planted secrets and leaks **none**, that classification
routes passwords→hash and secrets/PII→encrypt, that entropy **strictly increases** and the
weak passwords are flagged, and that the certificate is detected **EXPIRED**.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `python3: command not found` | Use `python` or install Python 3; run from this folder. |
| `FileNotFoundError` on a mock file | Run commands from `labs/lab-03-.../`; check the `mock-data/` path. |
| Scanner prints 0 findings | Confirm you pointed it at `mock-data/agent-config/` (the folder, not a file). |
| `--cert` says VALID | Ensure `mock-data/agent-cert.meta` exists (`notAfter: 2020-03-01T00:00:00Z`) or regenerate the cert with past dates (see below). |
| A secret value appears in your output | Stop — you edited the redaction. Restore `redact()`; never let a raw value reach a log or `evidence/`. |

**Regenerate the expired cert (optional):**

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null \
  -out mock-data/agent-cert.pem -subj "/CN=agent.local" \
  -not_before 20200101000000Z -not_after 20200301000000Z
```

If your `openssl` lacks `-not_before`/`-not_after`, generate a normal cert and keep
`mock-data/agent-cert.meta` — `--cert` prefers the `.meta` `notAfter`, so expiry stays
deterministic.

## Acceptance checklist

- [ ] `secret_scan.py` reports **exactly 5** secrets by **file + line**, all **redacted**
- [ ] `--classify` routes **passwords/integrity → HASH** and **PII/secrets/confidential → ENCRYPT**
- [ ] `--entropy` shows **strictly increasing** bits across the 4 tiers; the weak ones are **flagged**
- [ ] `--cert` reports issuer/subject/validity/key-size and flags the cert **EXPIRED**
- [ ] The OpenClaw review cited **file + line**, echoed **no** secret, and only **proposed** (human approval for rotate/revoke)
- [ ] `python3 verify.py` prints **PASS**
- [ ] No real secrets or personal data appear anywhere in your evidence
