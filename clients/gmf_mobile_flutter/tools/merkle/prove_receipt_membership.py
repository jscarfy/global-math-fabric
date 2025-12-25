#!/usr/bin/env python3
import argparse, json, hashlib, os
from typing import List, Tuple

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def canon_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8")

def build_merkle(leaves: List[bytes]) -> Tuple[bytes, List[List[bytes]]]:
    """
    returns (root, levels) where levels[0]=leaves
    odd duplication on each level
    """
    if not leaves:
        return sha256(b""), [[sha256(b"")]]
    levels=[leaves[:]]
    while len(levels[-1]) > 1:
        cur=levels[-1][:]
        if len(cur) % 2 == 1:
            cur.append(cur[-1])
        nxt=[]
        for i in range(0, len(cur), 2):
            nxt.append(sha256(cur[i] + cur[i+1]))
        levels.append(nxt)
    return levels[-1][0], levels

def merkle_proof(levels: List[List[bytes]], index: int) -> List[dict]:
    proof=[]
    idx=index
    for lvl in range(len(levels)-1):
        cur=levels[lvl]
        if len(cur) % 2 == 1:
            cur = cur + [cur[-1]]
        sib = idx ^ 1
        proof.append({
            "level": lvl,
            "index": idx,
            "sibling_index": sib,
            "sibling_hash": cur[sib].hex(),
            "direction": "left" if sib < idx else "right"
        })
        idx //= 2
    return proof

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--receipts", required=True, help="receipts.jsonl")
    ap.add_argument("--account", required=True, help="account_id")
    ap.add_argument("--day", required=True, help="YYYY-MM-DD (UTC)")
    ap.add_argument("--receipt_index", type=int, required=True, help="0-based index within that account/day in receipts.jsonl scan order")
    ap.add_argument("--out", required=True, help="proof.json")
    args=ap.parse_args()

    # collect receipts of that account/day
    leaves=[]
    chosen=None
    with open(args.receipts,"r",encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            r=json.loads(line)
            acct=(r.get("account") or {}).get("account_id","unknown")
            ts=str(r.get("ts") or r.get("issued_at") or "")
            day=ts[:10]
            if acct==args.account and day==args.day:
                leaf=sha256(canon_json(r))
                if len(leaves)==args.receipt_index:
                    chosen=r
                leaves.append(leaf)

    if chosen is None:
        raise SystemExit("receipt_index not found for that account/day")

    root, levels = build_merkle(leaves)
    proof = merkle_proof(levels, args.receipt_index)
    out={
        "account_id": args.account,
        "day": args.day,
        "receipt_index": args.receipt_index,
        "leaf_hash": leaves[args.receipt_index].hex(),
        "root": root.hex(),
        "proof": proof,
        "receipt": chosen,
        "verify_rule": "sha256(canonical_json(receipt)) as leaf; bitcoin-style duplicate-last on odd levels"
    }
    with open(args.out,"w",encoding="utf-8") as g:
        g.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")

if __name__=="__main__":
    main()
