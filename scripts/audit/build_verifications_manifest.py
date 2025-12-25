#!/usr/bin/env python3
import os, json, hashlib
from pathlib import Path
from datetime import datetime, timezone

VER_DIR = Path(os.environ.get("GMF_VERIFICATION_DIR", "ledger/verifications"))
OUT = Path(os.environ.get("GMF_VERIFICATIONS_MANIFESTS_DIR", "ledger/verifications/manifests"))

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

    # collect all verification records that have ts_utc matching day (best-effort)
    proofs = []
    if VER_DIR.exists():
        for sub in VER_DIR.glob("*"):
            if not sub.is_dir(): continue
            for f in sub.glob("*.json"):
                try:
                    obj = json.loads(f.read_text(encoding="utf-8"))
                    ts = obj.get("ts_utc") or ""
                    if ts.startswith(day):
                        proofs.append({
                            "proof_hash": f.stem,
                            "file": str(f),
                            "file_sha256": sha256_file(f),
                            "job_id": obj.get("job_id"),
                            "device_id": obj.get("device_id"),
                            "awarded_credits": obj.get("awarded_credits"),
                            "accepted": obj.get("accepted"),
                        })
                except Exception:
                    continue

    proofs.sort(key=lambda x: (x.get("job_id") or "", x.get("proof_hash") or ""))

    manifest = {
        "kind": "gmf_verifications_manifest",
        "version": 1,
        "date_utc": day,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "proof_count": len(proofs),
        "proofs": [{"proof_hash": p["proof_hash"], "file_sha256": p["file_sha256"]} for p in proofs],
        "notes": "Each proof_hash corresponds to sha256(canonical verification record json).",
    }

    mp = OUT / f"{day}.verifications.manifest.json"
    mp.write_bytes(canon_bytes(manifest))
    mh = hashlib.sha256(mp.read_bytes()).hexdigest()
    (OUT / f"{day}.verifications.manifest.sha256").write_text(mh + "\n", encoding="utf-8")

    print(json.dumps({"ok": True, "date": day, "manifest": str(mp), "manifest_sha256": mh, "proof_count": len(proofs)}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
