#!/usr/bin/env python3
"""trust_boundary.py — derive the AI-agent trust boundary from the security policy.

Standard library only. Reads the policy and emits a JSON model of the three zones
and the permission/approval gate, so the learner can render (in diagrams.net) a
trust-boundary diagram that matches the policy exactly.

  python3 trust_boundary.py --policy policy.yaml --out evidence/trust-boundary.json
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import miniyaml


def build(policy):
    assets = policy.get("assets", []) or []
    privileged = [a["name"] for a in assets if a.get("classification") == "Confidential"]
    tools = sorted({t for a in assets for t in (a.get("agent_tools") or []) if t and t != "none"})
    approval_required = [a["name"] for a in assets if a.get("state_changing") is True]
    return {
        "trust_boundary": {
            "untrusted_zone": {
                "description": "External, unauthenticated input — treated as data, never instructions.",
                "members": ["user_prompt", "external_web_content", "uploaded_files", "tool_output"],
            },
            "agent_core": {
                "description": "The trusted agent: model + security policy + prompt contract + scoped context/memory.",
                "prompt_contract": policy.get("prompt_contract"),
                "scoped_tools": tools,
            },
            "permission_gate": {
                "description": "Permission + human-approval gate for state-changing/sensitive actions.",
                "human_approval_required_for": approval_required,
            },
            "privileged_zone": {
                "description": "Scoped tools, sensitive data and external systems behind the gate.",
                "confidential_assets": privileged,
            },
        }
    }


def main():
    ap = argparse.ArgumentParser(description="Derive the agent trust boundary from the policy.")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    policy = miniyaml.load(args.policy)
    model = build(policy)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(model, f, indent=2)
    tb = model["trust_boundary"]
    print(f"Wrote {args.out}")
    print(f"  untrusted members : {len(tb['untrusted_zone']['members'])}")
    print(f"  scoped tools      : {tb['agent_core']['scoped_tools']}")
    print(f"  approval-gated     : {len(tb['permission_gate']['human_approval_required_for'])} asset(s)")
    print(f"  privileged assets  : {tb['privileged_zone']['confidential_assets']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
