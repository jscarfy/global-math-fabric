import os, json
from pathlib import Path
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/verification", tags=["verification"])

VER_DIR = Path(os.environ.get("GMF_VERIFICATION_DIR", "ledger/verifications"))

def _path_for_hash(h: str) -> Path:
    h = h.lower()
    if len(h) < 8:
        raise ValueError("hash too short")
    return VER_DIR / h[:2] / f"{h}.json"

@router.get("/{proof_hash}")
def get_verification(proof_hash: str):
    try:
        p = _path_for_hash(proof_hash)
    except Exception:
        raise HTTPException(status_code=400, detail="bad_hash")
    if not p.exists():
        raise HTTPException(status_code=404, detail="verification_not_found")
    obj = json.loads(p.read_text(encoding="utf-8"))
    return {"ok": True, "proof_hash": proof_hash, "verification": obj}
