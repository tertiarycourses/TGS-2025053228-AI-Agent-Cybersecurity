# Lab 2 — Evidence to Capture

Save your work here as you go. **Do not include model answers** — capture *your* outputs
and prompts so an assessor can see the workflow. Never store real emails, secrets or
personal data (the samples are synthetic; keep it that way).

Capture:

1. **Sample list** — the output of `ioc_extract.py --list mock-data/phish/`, showing the
   5 `.eml` samples that were triaged.
2. **Your tested regex** — the four patterns you built in the Regex Generator
   (<https://alfredang.github.io/regexgenerator/>) for `url`, `ipv4`, `sha256`, `sender`,
   plus a note of what each was tested against.
3. **`ioc-report.json`** — produced by `ioc_extract.py --patterns patterns.txt ...`, showing
   `counts_by_type` and every IOC with its **source file + line**.
4. **Scored view** — the `ioc_extract.py --score evidence/ioc-report.json` output, showing
   the confidence and the **observation vs inference** split.
5. **Agent transcript** — the Hermes IOC-triage prompt and its JSON output, showing every
   IOC **cited to a file + line** and that **no indicator was invented**.
6. **Human-approval record** — a short note recording who **approved** the awareness advisory
   the OpenClaw agent drafted, before it would be "sent" (nothing is actually sent).
7. **Acceptance** — the `verify.py` output ending in `RESULT: PASS`.

Suggested filenames: `01-list.txt`, `02-regex.md`, `ioc-report.json`, `04-score.txt`,
`05-hermes-triage.json`, `06-approval.md`, `07-verify.txt`.
