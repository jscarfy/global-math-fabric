#!/usr/bin/env python3
import argparse, json, hashlib, datetime

def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

ap = argparse.ArgumentParser()
ap.add_argument("--old-rules", default="governance/rules/v1.json")
ap.add_argument("--new-rules", default="governance/rules/v2.json")
ap.add_argument("--new-sigset", required=True, help="path to v2 sigset json")
ap.add_argument("--guardian-set-id", required=True)
ap.add_argument("--effective-from-entries", type=int, required=True, help="MUST be >= some signed checkpoint entries")
ap.add_argument("--out", default="/tmp/rules_amendment_request.json")
args = ap.parse_args()

old = json.load(open(args.old_rules,"r",encoding="utf-8"))
new = json.load(open(args.new_rules,"r",encoding="utf-8"))

old_sha = sha256_hex(canon(old))
new_sha = sha256_hex(canon(new))

ts = datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"
msg = f"GMF_RULES_AMEND|old:{old_sha}|new_ver:{new.get('rules_version','v2')}|new_path:{args.new_rules}|new_sigset:{args.new_sigset}|eff:{args.effective_from_entries}|set:{args.guardian_set_id}|ts:{ts}"

req = {
  "amendment_v": 1,
  "old_rules_sha256": old_sha,
  "new_rules_version": str(new.get("rules_version","v2")),
  "new_rules_path": args.new_rules,
  "new_sigset_path": args.new_sigset,
  "effective_from_checkpoint_entries": int(args.effective_from_entries),
  "guardian_set_id": args.guardian_set_id,
  "msg": msg,
  "sig_suite": "ed25519",
  "signatures": []
}

json.dump(req, open(args.out,"w",encoding="utf-8"), ensure_ascii=False, sort_keys=True, indent=2)
print("Wrote", args.out)
print("MSG:", msg)
