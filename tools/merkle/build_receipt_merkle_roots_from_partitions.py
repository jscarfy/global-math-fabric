#!/usr/bin/env python3
import argparse, glob, json, os, hashlib
from datetime import datetime, timezone

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def canon_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8")

def merkle_root(leaves):
    if not leaves:
        return sha256(b"")
    level = leaves[:]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt=[]
        for i in range(0, len(level), 2):
            nxt.append(sha256(level[i] + level[i+1]))
        level=nxt
    return level[0]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--day", required=True, help="YYYY-MM-DD (UTC)")
    ap.add_argument("--receipts_dir", default="ledger/receipts")
    ap.add_argument("--outdir", default="ledger/merkle_roots")
    args=ap.parse_args()

    pat = os.path.join(args.receipts_dir, "*", f"{args.day}.jsonl")
    files = sorted(glob.glob(pat))
    for fp in files:
        acct = os.path.basename(os.path.dirname(fp))
        leaves=[]
        concat=bytearray()
        with open(fp, "r", encoding="utf-8") as f:
            for line in f:
                line=line.strip()
                if not line: continue
                r=json.loads(line)
                leaf=sha256(canon_json(r))
                leaves.append(leaf)
                concat.extend(leaf)
        root=merkle_root(leaves).hex()
        leaves_sha=hashlib.sha256(bytes(concat)).hexdigest()
        out={
            "account_id": acct,
            "day": args.day,
            "count": len(leaves),
            "root": root,
            "leaves_sha256": leaves_sha,
        }
        od=os.path.join(args.outdir, acct)
        os.makedirs(od, exist_ok=True)
        with open(os.path.join(od, f"{args.day}.json"), "w", encoding="utf-8") as g:
            g.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")

if __name__=="__main__":
    main()
