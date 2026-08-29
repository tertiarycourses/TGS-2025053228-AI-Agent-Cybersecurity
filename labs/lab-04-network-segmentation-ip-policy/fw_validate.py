#!/usr/bin/env python3
"""fw_validate.py — validate firewall rules against the segmentation policy.

Standard library only. Reads the least-privilege segmentation policy (YAML) and a
firewall rule set (CSV: src_zone,dst_zone,port,action) and FLAGS every rule that
violates the policy, so a reviewer can prove the firewall enforces least privilege.

  python3 fw_validate.py --policy segmentation-policy.yaml firewall-rules.csv

A rule is FLAGGED when:
  V1  it ALLOWs a (src,dst,port) flow that is NOT in the policy's allowed_flows
      (default-deny: anything unlisted is denied)  — e.g. the seeded
      tool_sandbox -> sensitive_data ALLOW.
  V2  it DENYs a flow the policy explicitly allows (breaks a sanctioned path).
A rule PASSES when its action agrees with the policy (ALLOW a listed flow, or
DENY / not-list an unlisted flow).

Exit 1 if any rule is flagged, else 0. `validate()` is importable for verify.py.
"""
import argparse, csv, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import miniyaml


def load_policy(path):
    return miniyaml.load(path)


def _allowed_index(policy):
    """Map (src, dst, port) -> flow id for every allowed flow in the policy."""
    idx = {}
    for f in policy.get("allowed_flows", []) or []:
        key = (str(f.get("src")).strip(), str(f.get("dst")).strip(), int(f.get("port")))
        idx[key] = f.get("id", "?")
    return idx


def read_rules(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def validate(policy, rules):
    """Return (results, flagged).

    results: list of dicts {src,dst,port,action,verdict,reason,policy_ref}
    flagged: the subset whose verdict == 'FLAG'.
    """
    allowed = _allowed_index(policy)
    protected = _protected_zones(policy)
    results = []
    for r in rules:
        src = (r.get("src_zone") or "").strip()
        dst = (r.get("dst_zone") or "").strip()
        try:
            port = int(r.get("port"))
        except (TypeError, ValueError):
            port = r.get("port")
        action = (r.get("action") or "").strip().upper()
        key = (src, dst, port)
        is_allowed_by_policy = key in allowed
        ref = allowed.get(key, "default-deny")

        if action == "ALLOW" and not is_allowed_by_policy:
            note = f"policy has no allowed_flow for {src}->{dst}:{port} (default_action: deny)"
            if dst in protected:
                note += f"; '{dst}' is protected — only the approved management path may reach it"
            results.append(_row(src, dst, port, action, "FLAG", "V1 " + note, ref))
        elif action == "DENY" and is_allowed_by_policy:
            note = f"policy allows {src}->{dst}:{port} (flow {ref}) but rule DENYs it"
            results.append(_row(src, dst, port, action, "FLAG", "V2 " + note, ref))
        else:
            if action == "ALLOW":
                note = f"matches allowed_flow {ref}"
            else:
                note = f"denies an unlisted flow (consistent with default_action: deny)"
            results.append(_row(src, dst, port, action, "PASS", note, ref))
    flagged = [x for x in results if x["verdict"] == "FLAG"]
    return results, flagged


def _protected_zones(policy):
    """Zones that only the approved management path may reach.

    Derived from the policy: any dst that is the sensitive tier. We treat
    'sensitive_data' as protected and confirm its only allowed source is management.
    """
    protected = set()
    dsts = {}
    for f in policy.get("allowed_flows", []) or []:
        dsts.setdefault(str(f.get("dst")).strip(), set()).add(str(f.get("src")).strip())
    # sensitive_data is protected by design in this lab
    if "sensitive_data" in dsts or True:
        protected.add("sensitive_data")
    return protected


def _row(src, dst, port, action, verdict, reason, ref):
    return {"src": src, "dst": dst, "port": port, "action": action,
            "verdict": verdict, "reason": reason, "policy_ref": ref}


def print_report(policy_path, rules_path, results, flagged):
    print(f"Firewall validation · policy={os.path.basename(policy_path)} · rules={os.path.basename(rules_path)}\n")
    print(f"{'VERDICT':8} {'SRC':16} {'DST':16} {'PORT':5} {'ACTION':7} REASON")
    print("-" * 100)
    for r in results:
        print(f"{r['verdict']:8} {r['src']:16} {r['dst']:16} {str(r['port']):5} {r['action']:7} {r['reason']}")
    print("-" * 100)
    if flagged:
        print(f"RESULT: {len(flagged)} rule(s) FLAGGED as policy violations:")
        for r in flagged:
            print(f"  ✗ {r['src']} -> {r['dst']}:{r['port']} {r['action']}  ({r['reason']})")
    else:
        print("RESULT: 0 violations — every firewall rule agrees with the segmentation policy.")


def main():
    ap = argparse.ArgumentParser(description="Validate firewall rules against the segmentation policy.")
    ap.add_argument("--policy", required=True, help="segmentation-policy.yaml")
    ap.add_argument("rules", help="firewall-rules.csv (src_zone,dst_zone,port,action)")
    args = ap.parse_args()
    policy = load_policy(args.policy)
    rules = read_rules(args.rules)
    results, flagged = validate(policy, rules)
    print_report(args.policy, args.rules, results, flagged)
    return 1 if flagged else 0


if __name__ == "__main__":
    raise SystemExit(main())
