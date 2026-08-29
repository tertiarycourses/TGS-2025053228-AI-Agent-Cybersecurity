#!/usr/bin/env python3
"""crypto_check.py — decide hash-vs-encrypt, score password entropy, validate a cert.

Standard library only (hashlib is available but not required for the decisions here).
Three modes:

  --classify mock-data/data-items.csv
      Read (item,type) and print, per item, whether to HASH or ENCRYPT and WHY.
      HASH   → passwords and integrity checks: you only ever need to VERIFY the value,
               never read it back, so store a one-way digest (e.g. bcrypt/SHA-256).
      ENCRYPT→ confidential data, secrets and PII: you must recover the plaintext later,
               so use reversible authenticated encryption and manage the key.

  --entropy mock-data/creds-sample.txt
      Read one password per line and estimate its strength in BITS using the
      character-set model  bits = length * log2(pool_size)  (the pool is the union of
      the character classes the password uses). Flag anything below the policy floor.

  --cert mock-data/agent-cert.pem
      Report issuer / subject / validity window / RSA key size and flag the certificate
      EXPIRED when notAfter < now. notAfter is read from a sibling `<cert>.meta` file if
      present (line `notAfter: 2020-03-01T00:00:00Z`), else from the certificate itself
      via the standard-library ssl decoder. Either way the check is deterministic.
"""
import argparse
import csv
import datetime
import math
import os
import re
import ssl
import sys

# --- policy knobs -----------------------------------------------------------------
ENTROPY_FLOOR_BITS = 60  # passwords below this are flagged weak

# type -> (decision, reason). Anything unknown defaults to ENCRYPT (fail safe).
CLASSIFY_RULES = {
    "password":     ("HASH",    "credential is only ever verified, never read back"),
    "integrity":    ("HASH",    "need a tamper-evident digest, not the original bytes"),
    "pii":          ("ENCRYPT", "personal data must be recoverable but kept confidential"),
    "confidential": ("ENCRYPT", "sensitive business data must stay confidential and reversible"),
    "secret":       ("ENCRYPT", "API keys/tokens must be retrieved in plaintext at runtime"),
    "public":       ("NEITHER", "public data needs no confidentiality or integrity secret"),
}


# --- character-set entropy --------------------------------------------------------
def charset_size(pw):
    size = 0
    if any(c.islower() for c in pw):
        size += 26
    if any(c.isupper() for c in pw):
        size += 26
    if any(c.isdigit() for c in pw):
        size += 10
    if any((not c.isalnum()) and (not c.isspace()) for c in pw):
        size += 33  # printable ASCII punctuation, approximate pool
    if any(c.isspace() for c in pw):
        size += 1
    return size


def entropy_bits(pw):
    """Character-set entropy in bits: length * log2(pool). 0 for empty input."""
    if not pw:
        return 0.0
    pool = charset_size(pw)
    if pool <= 1:
        return 0.0
    return round(len(pw) * math.log2(pool), 1)


def classify(csv_path):
    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    print(f"{'ITEM':26} {'TYPE':13} {'DECISION':8} REASON")
    print("-" * 92)
    hashed = encrypted = 0
    for r in rows:
        item = r["item"].strip()
        typ = r["type"].strip().lower()
        decision, reason = CLASSIFY_RULES.get(typ, ("ENCRYPT", "unknown type — default to confidential"))
        if decision == "HASH":
            hashed += 1
        elif decision == "ENCRYPT":
            encrypted += 1
        print(f"{item[:25]:26} {typ[:12]:13} {decision:8} {reason}")
    print("-" * 92)
    print(f"{len(rows)} item(s) · {hashed} to HASH · {encrypted} to ENCRYPT")
    return rows


def score(txt_path):
    with open(txt_path, encoding="utf-8") as f:
        pwds = [ln.rstrip("\n") for ln in f if ln.strip() != ""]
    print(f"Password entropy (character-set model) · policy floor = {ENTROPY_FLOOR_BITS} bits")
    print(f"{'#':>2}  {'LEN':>3}  {'POOL':>4}  {'BITS':>6}  STATUS   PASSWORD (redacted)")
    print("-" * 72)
    weak = 0
    results = []
    for i, pw in enumerate(pwds, start=1):
        bits = entropy_bits(pw)
        pool = charset_size(pw)
        status = "OK" if bits >= ENTROPY_FLOOR_BITS else "WEAK"
        if status == "WEAK":
            weak += 1
        red = (pw[:1] + "*" * (len(pw) - 1)) if len(pw) > 1 else "*"
        print(f"{i:>2}  {len(pw):>3}  {pool:>4}  {bits:>6}  {status:6}   {red}")
        results.append((pw, bits, status))
    print("-" * 72)
    print(f"{len(pwds)} password(s) · {weak} below the {ENTROPY_FLOOR_BITS}-bit policy floor")
    return results


# --- certificate ------------------------------------------------------------------
def _fmt_name(seq):
    """Turn ssl's nested RDN tuple into 'CN=..., O=..., C=...'."""
    short = {"commonName": "CN", "organizationName": "O", "organizationalUnitName": "OU",
             "countryName": "C", "localityName": "L", "stateOrProvinceName": "ST"}
    parts = []
    for rdn in seq or ():
        for k, val in rdn:
            parts.append(f"{short.get(k, k)}={val}")
    return ", ".join(parts)


def _parse_notafter(s):
    """Accept OpenSSL's 'Mar  1 00:00:00 2020 GMT' or ISO 'YYYY-MM-DDTHH:MM:SSZ'."""
    s = s.strip()
    m = re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", s)
    if m:
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    return datetime.datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)


def _rsa_key_bits(pem_path):
    """Best-effort RSA modulus size via a minimal DER walk (stdlib only). None if unknown."""
    try:
        pem = open(pem_path, encoding="utf-8").read()
        der = ssl.PEM_cert_to_DER_cert(pem)
    except Exception:
        return None

    def read_len(b, i):
        n = b[i]; i += 1
        if n < 0x80:
            return n, i
        k = n & 0x7F
        return int.from_bytes(b[i:i + k], "big"), i + k

    oid = bytes.fromhex("06092a864886f70d0101010500")  # rsaEncryption OID + NULL
    j = der.find(oid)
    if j == -1:
        return None
    k = j + len(oid)
    try:
        if der[k] != 0x03:  # BIT STRING
            return None
        k += 1
        _blen, k = read_len(der, k)
        if der[k] != 0x00:  # unused-bits byte
            return None
        k += 1
        if der[k] != 0x30:  # SEQUENCE
            return None
        k += 1
        _seqlen, k = read_len(der, k)
        if der[k] != 0x02:  # INTEGER (modulus)
            return None
        k += 1
        modlen, k = read_len(der, k)
        mod = der[k:k + modlen]
        if mod and mod[0] == 0x00:
            mod = mod[1:]
        return len(mod) * 8
    except Exception:
        return None


def cert(pem_path, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    info = ssl._ssl._test_decode_cert(pem_path)
    issuer = _fmt_name(info.get("issuer"))
    subject = _fmt_name(info.get("subject"))
    not_before = info.get("notBefore", "")

    # Prefer an explicit .meta notAfter if present (keeps the lab deterministic across
    # openssl builds); else use the certificate's own notAfter. Accept either
    # '<cert>.pem.meta' or '<cert>.meta' (i.e. the extension swapped for .meta).
    root, _ext = os.path.splitext(pem_path)
    meta_candidates = [pem_path + ".meta", root + ".meta"]
    not_after_src = "certificate"
    not_after_raw = info.get("notAfter", "")
    for meta_path in meta_candidates:
        if os.path.exists(meta_path):
            for ln in open(meta_path, encoding="utf-8"):
                if ln.lower().startswith("notafter:"):
                    not_after_raw = ln.split(":", 1)[1].strip()
                    not_after_src = "meta"
                    break
            break

    not_after_dt = _parse_notafter(not_after_raw)
    expired = not_after_dt < now
    key_bits = _rsa_key_bits(pem_path)

    print(f"CERTIFICATE: {pem_path}")
    print("-" * 72)
    print(f"  subject     : {subject}")
    print(f"  issuer      : {issuer}")
    print(f"  notBefore   : {not_before}")
    print(f"  notAfter    : {not_after_raw}  (source: {not_after_src})")
    print(f"  key size    : {str(key_bits) + '-bit RSA' if key_bits else 'unknown'}")
    print(f"  checked at  : {now.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    status = "EXPIRED" if expired else "VALID"
    print(f"  STATUS      : {status}")
    print("-" * 72)
    if expired:
        print("Certificate is EXPIRED — propose renew/reissue (human approval required before revoke).")
    else:
        print("Certificate is within its validity window.")
    return {"subject": subject, "issuer": issuer, "not_after": not_after_raw,
            "key_bits": key_bits, "expired": expired}


def main():
    ap = argparse.ArgumentParser(description="Hash-vs-encrypt classifier, password entropy, and cert validation.")
    ap.add_argument("--classify", metavar="CSV", help="classify (item,type) rows as HASH or ENCRYPT")
    ap.add_argument("--entropy", metavar="TXT", help="score password entropy (one per line)")
    ap.add_argument("--cert", metavar="PEM", help="report cert issuer/subject/validity/key size; flag EXPIRED")
    args = ap.parse_args()
    if args.classify:
        classify(args.classify)
        return 0
    if args.entropy:
        score(args.entropy)
        return 0
    if args.cert:
        result = cert(args.cert)
        return 1 if result["expired"] else 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
