#!/usr/bin/env python3
import argparse, json, csv, sys
from collections import defaultdict

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--receipts", required=True, help="path to receipts.jsonl")
    ap.add_argument("--out", required=True, help="output csv")
    ap.add_argument("--top", type=int, default=200)
    args = ap.parse_args()

    tot = defaultdict(int)
    jobs = defaultdict(int)

    with open(args.receipts, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try:
                r=json.loads(line)
            except Exception:
                continue
            acct = (r.get("account") or {}).get("account_id","unknown")
            c = int(r.get("awarded_credits",0))
            tot[acct] += c
            jobs[acct] += 1

    rows = sorted(tot.items(), key=lambda kv: kv[1], reverse=True)[:args.top]
    with open(args.out, "w", newline="", encoding="utf-8") as g:
        w=csv.writer(g)
        w.writerow(["rank","account_id","total_credits","jobs"])
        for i,(acct,score) in enumerate(rows, start=1):
            w.writerow([i,acct,score,jobs[acct]])

if __name__ == "__main__":
    main()
