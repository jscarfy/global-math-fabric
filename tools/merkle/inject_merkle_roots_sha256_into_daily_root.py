#!/usr/bin/env python3
import argparse, glob, hashlib, json, os, re
from pathlib import Path

def sha256_file(p: str) -> bytes:
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''):
            h.update(b)
    return h.digest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--day", required=True, help="YYYY-MM-DD")
    ap.add_argument("--merkle_dir", default="ledger/merkle_roots")
    ap.add_argument("--daily_roots_dir", default="ledger/daily_roots")
    ap.add_argument("--dry_run", action="store_true")
    args=ap.parse_args()

    # hash all merkle root json files for that day
    files = sorted(glob.glob(os.path.join(args.merkle_dir, "*", f"{args.day}.json")))
    h=hashlib.sha256()
    for fp in files:
        h.update(sha256_file(fp))
    merkle_roots_sha256 = h.hexdigest()

    # locate daily_root json files that mention day or live under day folder
    cands = glob.glob(os.path.join(args.daily_roots_dir, "**", f"*{args.day}*.json"), recursive=True)
    if not cands:
        raise SystemExit(f"cannot find daily root json matching day {args.day} under {args.daily_roots_dir}")

    # pick candidate with largest size (often the main root)
    cands = sorted(cands, key=lambda p: os.path.getsize(p), reverse=True)
    target = cands[0]

    doc = json.loads(Path(target).read_text(encoding="utf-8"))
    doc["merkle_roots_sha256"] = merkle_roots_sha256
    doc["merkle_roots_day"] = args.day
    doc["merkle_roots_count_files"] = len(files)

    if args.dry_run:
        print("target:", target)
        print("merkle_roots_sha256:", merkle_roots_sha256)
        return

    Path(target).write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("updated", target)
    print("merkle_roots_sha256", merkle_roots_sha256)

if __name__=="__main__":
    main()
