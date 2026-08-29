#!/usr/bin/env python3
"""ioc_extract.py — extract Indicators of Compromise (IOCs) from phishing emails.

Standard library only (uses the `re` module for regex). Synthetic samples only.

Modes:
  --list DIR                      list the .eml samples the extractor will read
  --patterns FILE DIR             extract IOCs from every .eml in DIR using the
                                  regex catalogue FILE; write a JSON report to stdout
  --score REPORT.json             read a report and add a confidence score per IOC,
                                  separating OBSERVATION (the literal string) from
                                  INFERENCE (why it is suspicious)

Exact commands used in this lab:
  python3 ioc_extract.py --list mock-data/phish/
  python3 ioc_extract.py --patterns patterns.txt mock-data/phish/ > evidence/ioc-report.json
  python3 ioc_extract.py --score evidence/ioc-report.json

IOC types:
  url, ipv4, sha256, sender   come from the regex catalogue (patterns.txt)
  attachment                  comes from the built-in Content-Disposition rule below

Every reported IOC carries its source file and 1-based line number. The regexes are
scoped tightly so the extractor reports EXACTLY the seeded indicators and no phantoms.
"""
import argparse, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Built-in rule for attachments (not a regex-catalogue type): an attachment is a
# Content-Disposition header that declares attachment with a filename=.
ATTACHMENT_RE = re.compile(
    r'^Content-Disposition:\s*attachment;\s*filename="?([^"\r\n]+)"?', re.IGNORECASE)

# Order in which types are reported / charted.
TYPE_ORDER = ["url", "ipv4", "sha256", "sender", "attachment"]

# Why each indicator type is suspicious — the INFERENCE half of --score. This is
# reasoning about the type, never invented evidence; the OBSERVATION stays literal.
INFERENCE = {
    "url": "Actionable link in an unsolicited message; verify the domain before any click.",
    "ipv4": "Sending/relay host address from the headers; check it against threat intel.",
    "sha256": "File digest referenced in the body; look it up in a malware sandbox/registry.",
    "sender": "From-header domain; look-alike or unexpected domains indicate spoofing.",
    "attachment": "Attached file; double extensions or macro types are common malware carriers.",
}

# Base confidence per type for --score (0..1). Refined by cheap heuristics below.
BASE_CONFIDENCE = {
    "url": 0.80, "ipv4": 0.70, "sha256": 0.85, "sender": 0.75, "attachment": 0.80,
}


def load_patterns(path):
    """Read patterns.txt -> list of (type, compiled_regex) preserving file order."""
    pats = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            typ, _, rx = line.partition("=")
            typ = typ.strip().lower()
            try:
                pats.append((typ, re.compile(rx, re.IGNORECASE if typ == "sender" else 0)))
            except re.error as e:
                print(f"pattern error for '{typ}': {e}", file=sys.stderr)
                raise
    return pats


def list_emails(directory):
    """Return the sorted list of .eml file paths under directory."""
    if not os.path.isdir(directory):
        raise NotADirectoryError(directory)
    return sorted(
        os.path.join(directory, n) for n in os.listdir(directory)
        if n.lower().endswith(".eml"))


def _rel(path):
    """Report paths relative to the lab folder for stable, portable evidence."""
    try:
        return os.path.relpath(path, HERE)
    except ValueError:
        return path


def extract_file(path, patterns):
    """Yield IOC dicts for one .eml file, each with source file + 1-based line number."""
    iocs = []
    src = _rel(path)
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    for lineno, line in enumerate(lines, start=1):
        # Catalogue-driven indicators (url, ipv4, sha256, sender, ...).
        for typ, rx in patterns:
            if typ == "sender":
                m = rx.search(line)
                if m:
                    iocs.append(_ioc(typ, m.group(1), src, lineno))
            else:
                for m in rx.finditer(line):
                    iocs.append(_ioc(typ, m.group(0), src, lineno))
        # Built-in attachment rule.
        am = ATTACHMENT_RE.search(line)
        if am:
            iocs.append(_ioc("attachment", am.group(1).strip(), src, lineno))
    return iocs


def _ioc(typ, value, src, lineno):
    return {"type": typ, "value": value, "file": src, "line": lineno}


def build_report(directory, patterns):
    """Extract every email in directory and assemble the JSON-able report."""
    files = list_emails(directory)
    all_iocs = []
    for p in files:
        all_iocs.extend(extract_file(p, patterns))
    counts = {t: sum(1 for i in all_iocs if i["type"] == t) for t in TYPE_ORDER}
    return {
        "tool": "ioc_extract.py",
        "source_dir": _rel(directory),
        "files_scanned": [_rel(p) for p in files],
        "counts_by_type": counts,
        "total": len(all_iocs),
        "iocs": all_iocs,
    }


def score_report(report):
    """Add a confidence score + observation/inference split to every IOC."""
    for i in report.get("iocs", []):
        typ = i["type"]
        conf = BASE_CONFIDENCE.get(typ, 0.5)
        val = i.get("value", "")
        # Cheap, transparent heuristics that raise confidence (documented, not invented).
        if typ == "attachment" and re.search(r"\.(exe|scr|js|xlsm|docm)$", val, re.IGNORECASE):
            conf = min(1.0, conf + 0.15)
        if typ == "attachment" and re.search(r"\.\w+\.(exe|scr|js)$", val, re.IGNORECASE):
            conf = min(1.0, conf + 0.05)  # double extension
        if typ == "url" and val.lower().startswith("http://"):
            conf = min(1.0, conf + 0.05)  # cleartext link
        i["observation"] = val                    # the literal string, verbatim
        i["inference"] = INFERENCE.get(typ, "Indicator warrants review.")
        i["confidence"] = round(conf, 2)
    report["scored"] = True
    return report


def print_scored(report):
    print(f"IOC SCORING · {report.get('source_dir', '?')} · {report.get('total', 0)} indicators")
    print(f"{'CONF':5} {'TYPE':11} {'SOURCE':34} {'OBSERVATION'}")
    print("-" * 100)
    for i in report["iocs"]:
        where = f"{i['file']}:{i['line']}"
        obs = i["observation"]
        if len(obs) > 40:
            obs = obs[:37] + "..."
        print(f"{i['confidence']:<5} {i['type']:11} {where[:33]:34} {obs}")
    print("-" * 100)
    c = report.get("counts_by_type", {})
    summary = " · ".join(f"{t}={c.get(t, 0)}" for t in TYPE_ORDER)
    print(f"by type: {summary}   (observation = literal string; inference = why suspicious)")


def main():
    ap = argparse.ArgumentParser(description="Extract IOCs from phishing emails (synthetic only).")
    ap.add_argument("--list", metavar="DIR", help="list the .eml samples that will be scanned")
    ap.add_argument("--patterns", metavar="FILE", help="regex catalogue file (patterns.txt)")
    ap.add_argument("--score", metavar="REPORT", help="add a confidence score to a JSON report")
    ap.add_argument("directory", nargs="?", help="directory of .eml files (with --patterns)")
    args = ap.parse_args()

    if args.list:
        files = list_emails(args.list)
        print(f"{len(files)} .eml sample(s) in {_rel(args.list)}:")
        for p in files:
            print("  " + _rel(p))
        return 0

    if args.score:
        with open(args.score, encoding="utf-8") as f:
            report = json.load(f)
        print_scored(score_report(report))
        return 0

    if args.patterns:
        directory = args.directory or "mock-data/phish/"
        patterns = load_patterns(args.patterns)
        report = build_report(directory, patterns)
        print(json.dumps(report, indent=2))
        return 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
