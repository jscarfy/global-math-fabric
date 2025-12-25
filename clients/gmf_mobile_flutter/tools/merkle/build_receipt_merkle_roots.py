#!/usr/bin/env python3
import argparse, json, os, hashlib
from collections import defaultdict
from datetime import datetime, timezone

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def canon_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8")

def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return sha256(b"")
    level = leaves[:]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt=[]
        for i in range(0, len(level), 2):
            nxt.append(sha256(level[i] + level[i+1]))
        level = nxt
    return level[0]

def day_utc(ts_iso: str) -> str:
    # expects Z or iso; fallback: treat as UTC string prefix
    try:
        dt = datetime.fromisoformat(ts_iso.replace("Z","+00:00")).astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return ts_iso[:10]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--receipts", required=True)
    ap.add_argument("--outdir", default="ledger/merkle_roots")
    args=ap.parse_args()

    groups = defaultdict(list)  # (account, day) -> list of leaf hashes
    leaves_concat = defaultdict(bytearray)

    with open(args.receipts, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try:
                r=json.loads(line)
            except Exception:
                continue
            acct = (r.get("account") or {}).get("account_id","unknown")
            ts = r.get("ts") or (r.get("issued_at") or "")
            d = day_utc(str(ts))
            leaf = sha256(canon_json(r))
            groups[(acct,d)].append(leaf)
            leaves_concat[(acct,d)].extend(leaf)

    for (acct,d), leaves in groups.items():
        root = merkle_root(leaves)
        leaves_sha = hashlib.sha256(bytes(leaves_concat[(acct,d)])).hexdigest()
        out = {
            "account_id": acct,
            "day": d,
            "count": len(leaves),
            "root": root.hex(),
            "leaves_sha256": leaves_sha,
        }
        od = os.path.join(args.outdir, acct)
        os.makedirs(od, exist_ok=True)
        with open(os.path.join(od, f"{d}.json"), "w", encoding="utf-8") as g:
            g.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")

if __name__=="__main__":
    main()
