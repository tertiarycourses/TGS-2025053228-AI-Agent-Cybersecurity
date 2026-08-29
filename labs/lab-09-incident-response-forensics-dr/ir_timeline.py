#!/usr/bin/env python3
"""ir_timeline.py — build an incident-response timeline from an event log.

Standard library only (json). Reads a JSONL file where each line is one incident
event tagged with an IR phase, then emits an ordered timeline as JSON to stdout:

  python3 ir_timeline.py mock-data/incident-events.jsonl > evidence/timeline.json

Events are ordered first by IR phase (prepare -> detect -> contain -> eradicate ->
recover -> learn) and then chronologically by timestamp within each phase. For every
event the timeline keeps OBSERVATION (the recorded facts of the event) strictly
separate from INFERENCE (the analyst's conclusion about the attacker's action), so a
reviewer can always tell evidence apart from interpretation.
"""
import json
import sys

# Canonical order of the six IR phases. This is the source of truth the verifier
# also imports, so the timeline and the acceptance check can never disagree.
PHASES = ["prepare", "detect", "contain", "eradicate", "recover", "learn"]
PHASE_RANK = {p: i for i, p in enumerate(PHASES)}


def load_events(path):
    """Read a JSONL file into a list of event dicts (blank lines ignored)."""
    events = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise SystemExit(f"line {lineno}: invalid JSON: {e}")
    return events


def build(events):
    """Return the ordered timeline model (dict ready for json.dump)."""
    # Order by phase rank, then by timestamp (ISO-8601 strings sort chronologically).
    # Unknown phases sort last so bad data is visible rather than silently reordered.
    ordered = sorted(
        events,
        key=lambda e: (PHASE_RANK.get(e.get("phase"), len(PHASES)), e.get("ts", "")),
    )
    timeline = []
    for i, e in enumerate(ordered, 1):
        timeline.append({
            "seq": i,
            "ts": e.get("ts"),
            "phase": e.get("phase"),
            "source": e.get("source"),
            "observation": e.get("observation"),  # event facts (evidence)
            "inference": e.get("inference"),      # attacker action (interpretation)
        })
    phases_present = [p for p in PHASES if any(e.get("phase") == p for e in events)]
    return {
        "incident": "agent-data-exfiltration",
        "phase_order": PHASES,
        "phases_present": phases_present,
        "all_phases_present": phases_present == PHASES,
        "event_count": len(timeline),
        "timeline": timeline,
    }


def main(argv):
    if len(argv) != 2:
        print("usage: python3 ir_timeline.py <incident-events.jsonl>", file=sys.stderr)
        return 2
    model = build(load_events(argv[1]))
    json.dump(model, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
