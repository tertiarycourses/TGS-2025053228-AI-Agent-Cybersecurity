#!/usr/bin/env python3
"""forensics.py — preserve artifacts and write a chain-of-custody log.

Standard library only (hashlib, csv). Given a directory of forensic artifacts, it
computes a SHA-256 digest of each file and records a chain-of-custody row so their
integrity can be re-verified later:

  python3 forensics.py --preserve mock-data/artifacts/ --log evidence/custody.csv

The custody log columns are: artifact, sha256, size, preserved_at, handler.
The hash and size are computed from the file bytes, so re-running on unchanged
artifacts reproduces IDENTICAL digests (the integrity property the verifier asserts).
The preserved_at timestamp is fixed and deterministic by design (it is a record of
*this preservation run's* declared time, seeded from the artifact bytes is avoided so
the demo stays reproducible) — real handlers would stamp the wall-clock collection time.
"""
import argparse
import csv
import hashlib
import os

# Fixed preservation timestamp and handler so the lab is fully reproducible and the
# verifier can assert byte-for-byte identical custody rows across runs. In a real
# investigation these would be the actual collection time and the named handler.
PRESERVED_AT = "2026-03-12T02:00:00Z"
HANDLER = "forensics-oncall"
FIELDS = ["artifact", "sha256", "size", "preserved_at", "handler"]


def sha256_of(path):
    """Return the SHA-256 hex digest of a file, read in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def preserve(artifacts_dir):
    """Hash every regular file in the directory; return custody rows sorted by name."""
    rows = []
    for name in sorted(os.listdir(artifacts_dir)):
        path = os.path.join(artifacts_dir, name)
        if not os.path.isfile(path):
            continue
        rows.append({
            "artifact": name,
            "sha256": sha256_of(path),
            "size": os.path.getsize(path),
            "preserved_at": PRESERVED_AT,
            "handler": HANDLER,
        })
    return rows


def write_log(rows, log_path):
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
    with open(log_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description="Preserve artifacts and write a chain-of-custody log.")
    ap.add_argument("--preserve", required=True, metavar="DIR", help="directory of artifacts to hash")
    ap.add_argument("--log", required=True, metavar="CSV", help="chain-of-custody CSV to write")
    args = ap.parse_args()
    rows = preserve(args.preserve)
    write_log(rows, args.log)
    print(f"Preserved {len(rows)} artifact(s) -> {args.log}")
    for r in rows:
        print(f"  {r['artifact']:16} {r['sha256']}  {r['size']} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
