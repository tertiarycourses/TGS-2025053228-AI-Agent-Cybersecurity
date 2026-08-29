#!/usr/bin/env python3
"""log_investigate.py — investigate synthetic firewall + auth logs (Lab 7).

Standard library only (re, json, collections). No third-party packages.

Three modes map 1:1 to the lab commands:

  --fw FIREWALL.LOG
      Print a summary of DENY events: counts by SOURCE and by DESTINATION PORT.

  --detect-bruteforce FIREWALL.LOG            (write JSON to stdout / redirect)
      Detect a brute-force signature — many DENY events to ONE destination port
      from ONE source inside a short time window — and emit a timeline.json with
      the raw OBSERVATIONS (the exact log lines) and a single INFERENCE.

  --auth AUTH.LOG
      Summarise the system auth log and CONFIRM whether the attacker IP ever got a
      successful login (it must not — network segmentation blocked it).

A firewall line looks like:
  2026-07-06T09:11:03 DENY TCP 198.51.100.45 10.0.1.10 4444 3389 inbound
  (timestamp action proto src dst sport dport direction)

An auth line looks like:
  2026-07-06T09:11:05 AUTH FAILURE user=administrator source=198.51.100.45 reason=... host=rdp-gw
"""
import argparse
import json
import re
import sys
from collections import Counter, defaultdict

# The IP the rest of the lab investigates. Kept here so --auth can confirm it never
# succeeded; the detector below does NOT use it — it finds the attacker from the data.
ATTACKER_IP = "198.51.100.45"

# Brute-force thresholds: >= MIN_EVENTS DENY to one (source, dport) within WINDOW seconds.
BRUTEFORCE_MIN_EVENTS = 10
BRUTEFORCE_WINDOW_SECONDS = 600

FW_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<action>\S+)\s+(?P<proto>\S+)\s+"
    r"(?P<src>\S+)\s+(?P<dst>\S+)\s+(?P<sport>\d+)\s+(?P<dport>\d+)\s+(?P<dir>\S+)\s*$"
)

AUTH_RE = re.compile(
    r"^(?P<ts>\S+)\s+AUTH\s+(?P<result>SUCCESS|FAILURE)\s+"
    r"user=(?P<user>\S+)\s+source=(?P<src>\S+)"
)


def _ts_to_seconds(ts):
    """Convert an ISO-ish timestamp 'YYYY-MM-DDThh:mm:ss' to a comparable integer.

    Standard-library-only, no datetime parsing needed for ordering within one day.
    Falls back to 0 on anything unexpected so the tool never crashes on a bad line.
    """
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})$", ts)
    if not m:
        return 0
    y, mo, d, hh, mm, ss = (int(x) for x in m.groups())
    # days since a fixed epoch is unnecessary for a single-day log; fold date in coarsely.
    return ((((y * 12 + mo) * 31 + d) * 24 + hh) * 60 + mm) * 60 + ss


def parse_firewall(path):
    """Return a list of dict rows for every well-formed firewall line."""
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            m = FW_RE.match(line)
            if not m:
                continue
            row = m.groupdict()
            row["line"] = line
            row["_sec"] = _ts_to_seconds(row["ts"])
            rows.append(row)
    return rows


def parse_auth(path):
    """Return a list of dict rows for every well-formed auth line."""
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            m = AUTH_RE.match(line)
            if not m:
                continue
            row = m.groupdict()
            row["line"] = line
            rows.append(row)
    return rows


def deny_summary(rows):
    """Return (by_source Counter, by_dport Counter) over DENY events only."""
    by_source = Counter()
    by_dport = Counter()
    for r in rows:
        if r["action"] == "DENY":
            by_source[r["src"]] += 1
            by_dport[r["dport"]] += 1
    return by_source, by_dport


def cmd_fw(path):
    rows = parse_firewall(path)
    total = len(rows)
    denies = [r for r in rows if r["action"] == "DENY"]
    allows = [r for r in rows if r["action"] == "ALLOW"]
    by_source, by_dport = deny_summary(rows)

    print(f"FIREWALL SUMMARY — {path}")
    print(f"  parsed {total} events: {len(allows)} ALLOW, {len(denies)} DENY\n")

    print("  DENY by destination port")
    print("  " + "-" * 34)
    for port, n in sorted(by_dport.items(), key=lambda kv: (-kv[1], int(kv[0]))):
        print(f"    port {port:>5} : {n:>3} DENY")
    print()

    print("  DENY by source IP")
    print("  " + "-" * 34)
    for src, n in sorted(by_source.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"    {src:<16} : {n:>3} DENY")
    print()

    top_src, top_src_n = (by_source.most_common(1) or [(None, 0)])[0]
    top_port, top_port_n = (by_dport.most_common(1) or [(None, 0)])[0]
    print(f"  Most-blocked source : {top_src} ({top_src_n} DENY)")
    print(f"  Most-targeted port  : {top_port} ({top_port_n} DENY)")
    return 0


def detect_bruteforce(rows):
    """Find the strongest brute-force signature in the DENY events.

    Groups DENY events by (source, destination port), and flags any group with
    >= BRUTEFORCE_MIN_EVENTS events whose span is <= BRUTEFORCE_WINDOW_SECONDS.
    Returns the winning group's dict, or None. The detector is data-driven: it does
    not assume which IP or port is the attacker.
    """
    groups = defaultdict(list)
    for r in rows:
        if r["action"] == "DENY":
            groups[(r["src"], r["dport"])].append(r)

    best = None
    for (src, dport), evs in groups.items():
        if len(evs) < BRUTEFORCE_MIN_EVENTS:
            continue
        evs_sorted = sorted(evs, key=lambda r: r["_sec"])
        span = evs_sorted[-1]["_sec"] - evs_sorted[0]["_sec"]
        if span > BRUTEFORCE_WINDOW_SECONDS:
            continue
        cand = {
            "source": src,
            "dest_port": dport,
            "dest": evs_sorted[0]["dst"],
            "count": len(evs_sorted),
            "window_seconds": span,
            "first_ts": evs_sorted[0]["ts"],
            "last_ts": evs_sorted[-1]["ts"],
            "events": evs_sorted,
        }
        # Prefer the group with the most events (then the tighter window).
        if best is None or (cand["count"], -cand["window_seconds"]) > (best["count"], -best["window_seconds"]):
            best = cand
    return best


def build_timeline(path):
    """Build the timeline.json structure (dict) for --detect-bruteforce."""
    rows = parse_firewall(path)
    bf = detect_bruteforce(rows)

    if not bf:
        return {
            "source_log": path,
            "detected": False,
            "observations": [],
            "inference": "no brute-force signature detected",
            "requires_human_approval": True,
        }

    port_service = {"3389": "RDP", "445": "SMB", "22": "SSH", "443": "HTTPS", "53": "DNS"}
    service = port_service.get(bf["dest_port"], f"port {bf['dest_port']}")

    observations = [
        {
            "ts": e["ts"],
            "action": e["action"],
            "src": e["src"],
            "dst": e["dst"],
            "dport": e["dport"],
            "log_line": e["line"],
        }
        for e in bf["events"]
    ]

    return {
        "source_log": path,
        "detected": True,
        "signature": {
            "type": "brute_force",
            "source": bf["source"],
            "dest": bf["dest"],
            "dest_port": bf["dest_port"],
            "service": service,
            "deny_count": bf["count"],
            "window_seconds": bf["window_seconds"],
            "first_ts": bf["first_ts"],
            "last_ts": bf["last_ts"],
        },
        "observations": observations,
        "inference": (
            f"attempted {service} brute force: {bf['count']} DENY events to port "
            f"{bf['dest_port']} on {bf['dest']} from a single source {bf['source']} "
            f"within {bf['window_seconds']}s"
        ),
        "recommended_next_step": (
            "PROPOSE a detection rule / block for the source IP — requires human "
            "approval before deployment (propose-only)."
        ),
        "requires_human_approval": True,
    }


def cmd_detect_bruteforce(path):
    timeline = build_timeline(path)
    # Emit ONLY the JSON on stdout so it can be redirected to evidence/timeline.json.
    print(json.dumps(timeline, indent=2))
    return 0


def cmd_auth(path):
    rows = parse_auth(path)
    total = len(rows)
    successes = [r for r in rows if r["result"] == "SUCCESS"]
    failures = [r for r in rows if r["result"] == "FAILURE"]

    attacker_success = [r for r in successes if r["src"] == ATTACKER_IP]
    attacker_failure = [r for r in failures if r["src"] == ATTACKER_IP]

    print(f"AUTH SUMMARY — {path}")
    print(f"  parsed {total} events: {len(successes)} SUCCESS, {len(failures)} FAILURE\n")

    print(f"  Events from attacker IP {ATTACKER_IP}")
    print("  " + "-" * 46)
    if attacker_failure or attacker_success:
        for r in attacker_failure + attacker_success:
            print(f"    {r['result']:<7} user={r['user']}  ({r['line']})")
    else:
        print("    (none)")
    print()

    if attacker_success:
        print(f"  RESULT: attacker {ATTACKER_IP} HAS a successful login — COMPROMISE.")
    else:
        print(f"  CONFIRMED: NO successful login from {ATTACKER_IP} "
              f"({len(attacker_failure)} failed attempt(s), all blocked).")
        print("  Interpretation: network segmentation blocked the RDP brute force at the gateway.")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Investigate synthetic firewall and auth logs (Lab 7).")
    ap.add_argument("--fw", metavar="FIREWALL_LOG",
                    help="print a DENY summary (by source and by destination port)")
    ap.add_argument("--detect-bruteforce", metavar="FIREWALL_LOG", dest="detect",
                    help="detect the brute-force source+port and emit timeline.json to stdout")
    ap.add_argument("--auth", metavar="AUTH_LOG",
                    help="summarise the auth log and confirm no successful attacker login")
    args = ap.parse_args()

    if args.fw:
        return cmd_fw(args.fw)
    if args.detect:
        return cmd_detect_bruteforce(args.detect)
    if args.auth:
        return cmd_auth(args.auth)

    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
