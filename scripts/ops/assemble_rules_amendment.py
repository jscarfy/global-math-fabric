#!/usr/bin/env python3
import argparse, json, glob, os, sys

ap = argparse.ArgumentParser()
ap.add_argument("--request", required=True)
ap.add_argument("--fragments", required=True, help="dir or glob")
ap.add_argument("--out", default="/tmp/signed_rules_amendment.json")
args = ap.parse_args()

req = json.load(open(args.request,"r",encoding="utf-8"))
paths = sorted(glob.glob(os.path.join(args.fragments, "*.json"))) if os.path.isdir(args.fragments) else sorted(glob.glob(args.fragments))

seen=set()
sigs=[]
for fp in paths:
    try:
        d=json.load(open(fp,"r",encoding="utf-8"))
        sid=str(d.get("signer") or "")
        sb=str(d.get("sig_b64") or "")
        if not sid or not sb or sid in seen: 
            continue
        seen.add(sid)
        sigs.append({"signer":sid,"sig_b64":sb})
    except Exception:
        pass

# threshold comes from guardian set; request doesn't carry it, so just require >=1 (server checks real threshold)
if len(sigs) < 1:
    print("ERROR: no fragments", file=sys.stderr)
    sys.exit(2)

signed=dict(req)
signed["signatures"]=sigs
json.dump(signed, open(args.out,"w",encoding="utf-8"), ensure_ascii=False, sort_keys=True, indent=2)
print("Wrote", args.out, "signers=", [x["signer"] for x in sigs])
