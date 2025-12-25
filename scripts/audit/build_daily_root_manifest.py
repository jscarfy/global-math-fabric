#!/usr/bin/env python3
import os, json, hashlib
from pathlib import Path
from datetime import datetime, timezone

REC_MAN_DIR = Path(os.environ.get("GMF_RECEIPTS_MANIFESTS_DIR", "ledger/receipts/manifests"))
VER_MAN_DIR = Path(os.environ.get("GMF_VERIFICATIONS_MANIFESTS_DIR", "ledger/verifications/manifests"))
XLINK_MAN_DIR = Path(os.environ.get("GMF_XLINKS_MANIFESTS_DIR", "ledger/xlinks/manifests"))
AUD_BUNDLE_MAN_DIR = Path(os.environ.get("GMF_AUDIT_BUNDLES_MANIFESTS_DIR", "ledger/audit_bundles/manifests"))
AUD_TR_MAN_DIR = Path(os.environ.get("GMF_AUDIT_TRANSCRIPTS_MANIFESTS_DIR", "ledger/audit_transcripts/manifests"))
OUT_DIR = Path(os.environ.get("GMF_DAILY_ROOTS_DIR", "ledger/daily_roots"))

def canon_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def sha256_path(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    rec = REC_MAN_DIR / f"{day}.manifest.json"
    ver = VER_MAN_DIR / f"{day}.verifications.manifest.json"
    xlm = XLINK_MAN_DIR / f"{day}.xlinks.manifest.json"
    abm = AUD_BUNDLE_MAN_DIR / f"{day}.audit_bundles.manifest.json"
    atm = AUD_TR_MAN_DIR / f"{day}.audit_transcripts.manifest.json"

    root = {
        "kind": "gmf_daily_root_manifest",
        "version": 1,
        "date_utc": day,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "receipts_manifest": {"path": str(rec), "sha256": sha256_path(rec)} if rec.exists() else None,
        "verifications_manifest": {"path": str(ver), "sha256": sha256_path(ver)} if ver.exists() else None,
        "xlinks_manifest": {"path": str(xlm), "sha256": sha256_path(xlm)} if xlm.exists() else None,
        "audit_bundles_manifest": {"path": str(abm), "sha256": sha256_path(abm)} if abm.exists() else None,
        "audit_transcripts_manifest": {"path": str(atm), "sha256": sha256_path(atm)} if atm.exists() else None,
        "notes": "Audit chain should hash only this daily root (public), not private receipts content.",
    }

    rp = OUT_DIR / f"{day}.root.json"
    rp.write_bytes(canon_bytes(root))
    rh = hashlib.sha256(rp.read_bytes()).hexdigest()
    (OUT_DIR / f"{day}.root.sha256").write_text(rh + "\n", encoding="utf-8")
    (OUT_DIR / "latest.root.json").write_bytes(canon_bytes(root))

    print(json.dumps({"ok": True, "date": day, "root": str(rp), "root_sha256": rh}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
