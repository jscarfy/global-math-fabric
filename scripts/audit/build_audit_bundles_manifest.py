#!/usr/bin/env python3
import os, json, hashlib
from pathlib import Path
from datetime import datetime, timezone

BUNDLE_DIR = Path(os.environ.get("GMF_AUDIT_BUNDLE_DIR", "ledger/audit_bundles"))
OUT = Path(os.environ.get("GMF_AUDIT_BUNDLES_MANIFESTS_DIR", "ledger/audit_bundles/manifests"))

def canon_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def sha256_file(p: Path) -> str:
    h=hashlib.sha256()
    with p.open("rb") as f:
        for ch in iter(lambda: f.read(1024*1024), b""):
            h.update(ch)
    return h.hexdigest()

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    items=[]
    if BUNDLE_DIR.exists():
        for f in BUNDLE_DIR.glob("*.bin"):
            meta = f.with_suffix(".meta.json")
            # best-effort day filter: use meta ts if exists; else include all (OK for MVP)
            if meta.exists():
                try:
                    obj=json.loads(meta.read_text(encoding="utf-8"))
                    items.append({"proof_hash": obj.get("proof_hash") or f.stem, "bundle_sha256": obj.get("bundle_sha256"), "bytes": obj.get("bytes")})
                except Exception:
                    items.append({"proof_hash": f.stem, "bundle_sha256": sha256_file(f), "bytes": f.stat().st_size})
            else:
                items.append({"proof_hash": f.stem, "bundle_sha256": sha256_file(f), "bytes": f.stat().st_size})

    items.sort(key=lambda x: x["proof_hash"])
    man = {
        "kind":"gmf_audit_bundles_manifest",
        "version":1,
        "date_utc": day,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "count": len(items),
        "bundles": items,
        "notes":"Each bundle file is ledger/audit_bundles/<proof_hash>.bin (base64-decoded trace bundle).",
    }
    mp = OUT / f"{day}.audit_bundles.manifest.json"
    mp.write_bytes(canon_bytes(man))
    mh = hashlib.sha256(mp.read_bytes()).hexdigest()
    (OUT / f"{day}.audit_bundles.manifest.sha256").write_text(mh + "\n", encoding="utf-8")
    print(json.dumps({"ok":True,"manifest":str(mp),"manifest_sha256":mh,"count":len(items)}, ensure_ascii=False, indent=2))

if __name__=="__main__":
    main()
