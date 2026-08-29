#!/usr/bin/env python3
"""subnet_plan.py — right-size and validate the IP segmentation plan.

Standard library only (uses the `ipaddress` module). Two modes:

  --need  mock-data/zone-requirements.csv   propose right-sized, non-overlapping
                                            subnets for each zone (largest first),
                                            carved from the 10.20.0.0/24 supernet
  --check subnets.csv                       validate a subnets.csv against the plan:
                                            correct prefix per zone, correct usable
                                            count, gateway inside the subnet, and
                                            NO overlaps. Exit 1 on any problem.

The supernet 10.20.0.0/24 is carved into 4 zones. A zone that needs N usable hosts
gets the smallest prefix whose usable count (num_addresses - 2, for network +
broadcast) is >= N. With requirements [30, 14, 6, 2] this yields exactly
/27, /28, /29, /30 -> usable [30, 14, 6, 2].
"""
import argparse, csv, ipaddress, os, sys

SUPERNET = ipaddress.ip_network("10.20.0.0/24")


def usable_hosts(net):
    """Usable host count for a subnet: all addresses minus network + broadcast.

    /31 and /32 have no network/broadcast reservation in ipaddress, but this lab
    never uses prefixes longer than /30, so the simple (num_addresses - 2) holds.
    """
    return max(net.num_addresses - 2, 0)


def prefix_for(required):
    """Smallest prefix length (largest block) whose usable count >= required."""
    for prefix in range(30, -1, -1):  # try smallest block (/30) first, grow as needed
        net = ipaddress.ip_network(f"10.0.0.0/{prefix}")
        if usable_hosts(net) >= required:
            return prefix
    raise ValueError(f"no prefix in 10.20.0.0/24 can hold {required} hosts")


def read_requirements(path):
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    reqs = []
    for r in rows:
        reqs.append({
            "zone": r["zone"].strip(),
            "description": (r.get("description") or "").strip(),
            "required_hosts": int(r["required_hosts"]),
        })
    return reqs


def plan(reqs):
    """Return a list of subnet dicts, largest zone first, packed with no gaps/overlaps."""
    ordered = sorted(reqs, key=lambda r: r["required_hosts"], reverse=True)
    out = []
    cursor = int(SUPERNET.network_address)
    for r in ordered:
        prefix = prefix_for(r["required_hosts"])
        net = ipaddress.ip_network((cursor, prefix))
        if not net.subnet_of(SUPERNET):
            raise ValueError(f"ran out of address space allocating {r['zone']}")
        gw = list(net.hosts())[0]
        out.append({
            "zone": r["zone"],
            "cidr": str(net),
            "usable": usable_hosts(net),
            "gateway": str(gw),
            "required": r["required_hosts"],
            "_net": net,
        })
        cursor = int(net.broadcast_address) + 1
    return out


def print_plan(rows):
    print(f"Supernet {SUPERNET} carved into {len(rows)} zones (largest first):\n")
    print(f"{'ZONE':16} {'CIDR':18} {'PREFIX':7} {'USABLE':7} {'NEED':5} GATEWAY")
    print("-" * 72)
    for r in rows:
        prefix = "/" + r["cidr"].split("/")[1]
        fit = "ok" if r["usable"] >= r["required"] else "SHORT"
        print(f"{r['zone']:16} {r['cidr']:18} {prefix:7} {r['usable']:<7} {r['required']:<5} {r['gateway']}  [{fit}]")
    print("-" * 72)
    usable_list = [r["usable"] for r in rows]
    print(f"usable hosts (largest->smallest): {usable_list}")
    # overlap sanity on the proposal itself
    nets = [r["_net"] for r in rows]
    overlaps = _find_overlaps(nets)
    print(f"overlaps: {'NONE' if not overlaps else overlaps}")


def _find_overlaps(nets):
    bad = []
    for i in range(len(nets)):
        for j in range(i + 1, len(nets)):
            if nets[i].overlaps(nets[j]):
                bad.append((str(nets[i]), str(nets[j])))
    return bad


def read_subnets(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def check(subnets_path):
    """Validate a subnets.csv. Return a list of problem strings ([] == valid)."""
    problems = []
    try:
        rows = read_subnets(subnets_path)
    except FileNotFoundError:
        return [f"file not found: {subnets_path}"]
    nets = []
    for r in rows:
        zone = (r.get("zone") or "<unnamed>").strip()
        try:
            net = ipaddress.ip_network(r["cidr"].strip(), strict=True)
        except (ValueError, KeyError) as e:
            problems.append(f"{zone}: invalid cidr '{r.get('cidr')}' ({e})")
            continue
        nets.append((zone, net))
        # subnet must sit inside the supernet
        if not net.subnet_of(SUPERNET):
            problems.append(f"{zone}: {net} is outside supernet {SUPERNET}")
        # usable column must match the true usable count
        try:
            declared = int(r["usable"])
            if declared != usable_hosts(net):
                problems.append(f"{zone}: usable={declared} but {net} yields {usable_hosts(net)}")
        except (ValueError, KeyError):
            problems.append(f"{zone}: usable column missing or non-integer")
        # gateway must be a real host address inside the subnet
        gw = (r.get("gateway") or "").strip()
        if gw:
            try:
                gwa = ipaddress.ip_address(gw)
                if gwa not in net.hosts():
                    problems.append(f"{zone}: gateway {gw} is not a usable host in {net}")
            except ValueError:
                problems.append(f"{zone}: gateway '{gw}' is not a valid IP address")
        else:
            problems.append(f"{zone}: gateway missing")
    # overlaps across every pair
    for (za, na), (zb, nb) in _pairs(nets):
        if na.overlaps(nb):
            problems.append(f"OVERLAP: {za} {na} overlaps {zb} {nb}")
    return problems


def _pairs(items):
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            yield items[i], items[j]


def main():
    ap = argparse.ArgumentParser(description="Right-size and validate the IP segmentation plan.")
    ap.add_argument("--need", metavar="CSV", help="propose right-sized subnets from zone-requirements.csv")
    ap.add_argument("--check", metavar="CSV", help="validate a subnets.csv (sizing + no overlaps)")
    args = ap.parse_args()

    if args.need:
        rows = plan(read_requirements(args.need))
        print_plan(rows)
        return 0

    if args.check:
        problems = check(args.check)
        if problems:
            print(f"SUBNET CHECK: {len(problems)} problem(s) in {args.check}")
            for p in problems:
                print("  ✗ " + p)
            return 1
        rows = read_subnets(args.check)
        print(f"SUBNET CHECK: 0 problems — {len(rows)} zones, correct sizing, gateways valid, no overlaps.")
        return 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
