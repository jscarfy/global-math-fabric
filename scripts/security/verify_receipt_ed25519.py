#!/usr/bin/env python3
import argparse, json, base64, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def load_pub(path: str) -> Ed25519PublicKey:
    pem = open(path, "rb").read()
    k = serialization.load_pem_public_key(pem)
    if not isinstance(k, Ed25519PublicKey):
        raise ValueError("not ed25519 pubkey")
    return k

def verify_line(pk: Ed25519PublicKey, line: str) -> bool:
    env = json.loads(line)
    sig = base64.b64decode(env["signature_b64"])
    msg = base64.b64decode(env["payload_b64"])
    try:
        pk.verify(sig, msg)
        return True
    except Exception:
        return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pub", required=True, help="receipt ed25519 pub pem")
    ap.add_argument("--jsonl", required=True, help="receipts jsonl (each line = receipt envelope json)")
    args = ap.parse_args()

    pk = load_pub(args.pub)
    ok = 0
    bad = 0
    with open(args.jsonl, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line: 
                continue
            if verify_line(pk, line):
                ok += 1
            else:
                bad += 1
                print(f"BAD line {i}", file=sys.stderr)
    print(json.dumps({"ok": ok, "bad": bad}, indent=2))

if __name__ == "__main__":
    main()
