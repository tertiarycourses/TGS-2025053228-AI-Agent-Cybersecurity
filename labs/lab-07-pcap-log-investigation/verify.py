#!/usr/bin/env python3
"""verify.py — deterministic acceptance check for Lab 7.

Runs the lab tooling against the seeded fixtures and asserts the known-correct
results, so a PASS proves the firewall summary, the brute-force detector and the
auth confirmation all work and agree with the deck chart:

  1. DENY-by-destination-port counts equal EXACTLY 3389=37, 445=8, 22=5, 443=1, 53=0
  2. the brute-force source is 198.51.100.45 on port 3389 (RDP)
  3. auth.log shows NO successful login from that attacker IP (segmentation blocked it)
  4. every claim in the emitted timeline cites a real firewall.log line

Exit code 0 = PASS, 1 = FAIL.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import log_investigate as li  # noqa: E402

MD = os.path.join(HERE, "mock-data")
FW = os.path.join(MD, "firewall.log")
AUTH = os.path.join(MD, "auth.log")

EXPECTED_DENY_BY_PORT = {"3389": 37, "445": 8, "22": 5, "443": 1, "53": 0}
ATTACKER = "198.51.100.45"

fails = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


def main():
    print("Lab 7 — PCAP & Log Investigation · verifier\n")

    fw_rows = li.parse_firewall(FW)
    _by_source, by_dport = li.deny_summary(fw_rows)

    # 1) DENY-by-destination-port counts match the deck chart EXACTLY.
    for port, want in EXPECTED_DENY_BY_PORT.items():
        got = by_dport.get(port, 0)
        check(f"DENY to port {port} == {want} (got {got})", got == want)
    # 53 must be genuinely absent, and no *extra* DENY ports may exist.
    check("no DENY events to port 53", by_dport.get("53", 0) == 0)
    check("no unexpected DENY destination ports",
          set(by_dport) <= set(EXPECTED_DENY_BY_PORT))

    # 2) Brute-force detector points at the RDP attacker on 3389.
    timeline = li.build_timeline(FW)
    check("brute force detected", timeline.get("detected") is True)
    sig = timeline.get("signature", {})
    check(f"brute-force source is {ATTACKER}", sig.get("source") == ATTACKER)
    check("brute-force destination port is 3389", sig.get("dest_port") == "3389")
    check("brute-force service resolved to RDP", sig.get("service") == "RDP")
    check("brute-force deny_count is 37", sig.get("deny_count") == 37)
    check("all 37 DENY-to-3389 come from the one source",
          all(o["src"] == ATTACKER for o in timeline["observations"])
          and len(timeline["observations"]) == 37)
    check("inference names an attempted RDP brute force",
          "rdp brute force" in timeline.get("inference", "").lower())
    check("timeline is propose-only (requires human approval)",
          timeline.get("requires_human_approval") is True)

    # 3) Auth log confirms segmentation blocked the attacker — NO successful login.
    auth_rows = li.parse_auth(AUTH)
    attacker_success = [r for r in auth_rows
                        if r["result"] == "SUCCESS" and r["src"] == ATTACKER]
    attacker_failure = [r for r in auth_rows
                        if r["result"] == "FAILURE" and r["src"] == ATTACKER]
    check(f"NO successful login from {ATTACKER} in auth.log", attacker_success == [])
    check(f"attacker {ATTACKER} appears only as failed attempts",
          len(attacker_failure) >= 1)

    # 4) Every timeline claim cites a REAL firewall.log line (no fabricated evidence).
    real_lines = {r["line"] for r in fw_rows}
    every_cited_line_real = all(o["log_line"] in real_lines
                                for o in timeline["observations"])
    check("every timeline observation cites a real firewall.log line",
          every_cited_line_real)
    # And each cited line must itself be a DENY to 3389 from the attacker.
    every_cited_line_matches = all(
        (o["action"] == "DENY" and o["dport"] == "3389" and o["src"] == ATTACKER)
        for o in timeline["observations"])
    check("every cited line is a DENY to 3389 from the attacker",
          every_cited_line_matches)

    print()
    if fails:
        print(f"RESULT: FAIL ({len(fails)} check(s) failed)")
        return 1
    print("RESULT: PASS — all Lab 7 checks passed "
          "(DENY chart matches, RDP brute force from 198.51.100.45:3389, "
          "no successful attacker login, every claim cites a real log line).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
