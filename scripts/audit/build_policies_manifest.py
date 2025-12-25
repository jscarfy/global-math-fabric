#!/usr/bin/env python3
import os, json, hashlib
from pathlib import Path
from datetime import datetime, timezone

POL_DIR = Path(os.environ.get("GMF_POLICIES_DIR", "ledger/policies"))
OUT = Path(os.environ.get("GMF_POLICIES_MANIFESTS_DIR", "ledger/policies/manifests"))
CUR_POLICY_PATH = Path(os.environ.get("GMF_POLICY_PATH", "ledger/policies/credit_policy_v2_bundle_v1.md"))

def canon_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_file(p: Path) -> str:
    return sha256_bytes(p.read_bytes())

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    items = []
    if POL_DIR.exists():
        for f in sorted(POL_DIR.glob("*.md")):
            try:
                b = f.read_bytes()
                items.append({
                    "name": f.name,
                    "relpath": str(f),
                    "sha256": sha256_bytes(b),
                    "bytes": len(b),
                })
            except Exception:
                continue

    # current policy pointer (best-effort)
    cur = None
    if CUR_POLICY_PATH.exists():
        b = CUR_POLICY_PATH.read_bytes()
        cur = {"name": CUR_POLICY_PATH.name, "relpath": str(CUR_POLICY_PATH), "sha256": sha256_bytes(b), "bytes": len(b)}

    manifest = {
        "kind": "gmf_policies_manifest",
        "version": 1,
        "date_utc": day,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "count": len(items),
        "current_policy": cur,
        "policies": items,
        "notes": "This manifest anchors policy file contents (sha256) into the daily root chain.",
    }

    mp = OUT / f"{day}.policies.manifest.json"
    mp.write_bytes(canon_bytes(manifest))
    mh = sha256_file(mp)
    (OUT / f"{day}.policies.manifest.sha256").write_text(mh + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "date": day, "manifest": str(mp), "manifest_sha256": mh, "count": len(items)}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
