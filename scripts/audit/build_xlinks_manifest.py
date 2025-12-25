#!/usr/bin/env python3
import os, json, hashlib
from pathlib import Path
from datetime import datetime, timezone

XLINK_DIR = Path(os.environ.get("GMF_XLINK_DIR", "ledger/xlinks"))
OUT = Path(os.environ.get("GMF_XLINKS_MANIFESTS_DIR", "ledger/xlinks/manifests"))

def canon_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for ch in iter(lambda: f.read(1024*1024), b""):
            h.update(ch)
    return h.hexdigest()

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    items = []
    if XLINK_DIR.exists():
        for sub in XLINK_DIR.glob("*"):
            if not sub.is_dir(): continue
            for f in sub.glob("*.json"):
                try:
                    obj = json.loads(f.read_text(encoding="utf-8"))
                    ts = obj.get("ts_utc") or ""
                    if ts.startswith(day):
                        items.append({"xlink_hash": f.stem, "file_sha256": sha256_file(f)})
                except Exception:
                    continue
    items.sort(key=lambda x: x["xlink_hash"])
    manifest = {
        "kind": "gmf_xlinks_manifest",
        "version": 1,
        "date_utc": day,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "count": len(items),
        "xlinks": items,
        "notes": "Each xlink json hashes (proof_hash, receipt_hash, ts_utc) and is stored under ledger/xlinks/<xx>/<hash>.json",
    }
    mp = OUT / f"{day}.xlinks.manifest.json"
    mp.write_bytes(canon_bytes(manifest))
    mh = hashlib.sha256(mp.read_bytes()).hexdigest()
    (OUT / f"{day}.xlinks.manifest.sha256").write_text(mh + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "date": day, "manifest": str(mp), "manifest_sha256": mh, "count": len(items)}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
