#!/usr/bin/env python3
import hashlib, json, os

RECEIPTS="ledger/receipts/receipts.jsonl"

def h(b: bytes)->bytes:
    return hashlib.sha256(b).digest()

def merkle(leaves):
    if not leaves: return b"\x00"*32
    level=[h(x) for x in leaves]
    while len(level)>1:
        nxt=[]
        for i in range(0,len(level),2):
            a=level[i]
            b=level[i+1] if i+1<len(level) else level[i]
            nxt.append(h(a+b))
        level=nxt
    return level[0]

os.makedirs("ledger/roots", exist_ok=True)
if not os.path.exists(RECEIPTS):
    open(RECEIPTS,"a").close()

leaves=[]
with open(RECEIPTS,"r",encoding="utf-8") as f:
    for ln in f:
        ln=ln.strip()
        if ln:
            leaves.append(ln.encode("utf-8"))

root=merkle(leaves).hex()
print(root)
