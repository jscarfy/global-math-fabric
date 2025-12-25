#!/usr/bin/env python3
import argparse, json, glob, sys, os

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pending", required=True, help="pending checkpoint json")
    ap.add_argument("--fragments", required=True, help="directory or glob for fragment jsons (e.g. fragments/*.json)")
    ap.add_argument("--out", default="signed_checkpoint.json")
    args = ap.parse_args()

    pending = json.load(open(args.pending, "r", encoding="utf-8"))

    # collect fragments
    frag_paths = []
    if os.path.isdir(args.fragments):
        frag_paths = sorted(glob.glob(os.path.join(args.fragments, "*.json")))
    else:
        frag_paths = sorted(glob.glob(args.fragments))

    seen = set()
    sigs = []
    for fp in frag_paths:
        try:
            d = json.load(open(fp, "r", encoding="utf-8"))
            signer = str(d.get("signer") or "")
            sig_b64 = str(d.get("sig_b64") or "")
            if not signer or not sig_b64:
                continue
            if signer in seen:
                continue
            seen.add(signer)
            sigs.append({"signer": signer, "sig_b64": sig_b64})
        except Exception:
            continue

    threshold = int(pending.get("threshold") or 1)
    if len(sigs) < threshold:
        print(f"ERROR: not enough fragments. have={len(sigs)} need_threshold={threshold}", file=sys.stderr)
        sys.exit(2)

    # Build signed checkpoint
    signed = dict(pending)
    signed["signatures"] = sigs

    json.dump(signed, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, sort_keys=True, indent=2)
    print("Wrote:", args.out)
    print("Signers:", [x["signer"] for x in sigs])
    print("Threshold:", threshold)

if __name__ == "__main__":
    main()
