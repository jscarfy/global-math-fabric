#!/usr/bin/env python3
import sys, json, os, hashlib, time

RECEIPTS="ledger/receipts/receipts.jsonl"
os.makedirs(os.path.dirname(RECEIPTS), exist_ok=True)

line=sys.stdin.read().strip()
if not line:
    raise SystemExit("no input")
# store as-is (one envelope json per line)
with open(RECEIPTS, "a", encoding="utf-8") as f:
    f.write(line+"\n")

print("ok")
