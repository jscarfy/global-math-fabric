#!/usr/bin/env python3
import os, json, hashlib
from pathlib import Path
from datetime import datetime, timezone

TR_DIR = Path(os.environ.get("GMF_AUDIT_TRANSCRIPTS_DIR", "ledger/audit_transcripts"))
OUT = Path(os.environ.get("GMF_AUDIT_TRANSCRIPTS_MANIFESTS_DIR", "ledger/audit_transcripts/manifests"))

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
    if TR_DIR.exists():
        for f in TR_DIR.glob("*.json"):
            try:
                obj = json.loads(f.read_text(encoding="utf-8"))
                ts = obj.get("ts_utc","")
                if ts.startswith(day):
                    items.append({"proof_hash": obj.get("proof_hash") or f.stem, "file_sha256": sha256_file(f)})
            except Exception:
                continue

    items.sort(key=lambda x: x["proof_hash"])
    man = {
        "kind":"gmf_audit_transcripts_manifest",
        "version":1,
        "date_utc": day,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "count": len(items),
        "transcripts": items,
        "notes":"Each transcript records seed/chunk_size/sample_k/num_chunks/root and verification result.",
    }
    mp = OUT / f"{day}.audit_transcripts.manifest.json"
    mp.write_bytes(canon_bytes(man))
    mh = hashlib.sha256(mp.read_bytes()).hexdigest()
    (OUT / f"{day}.audit_transcripts.manifest.sha256").write_text(mh + "\n", encoding="utf-8")
    print(json.dumps({"ok":True,"manifest":str(mp),"manifest_sha256":mh,"count":len(items)}, ensure_ascii=False, indent=2))

if __name__=="__main__":
    main()
