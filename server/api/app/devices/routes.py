from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from .store import append_device_event, load_devices_index, _now

router = APIRouter(prefix="/api/device", tags=["device"])

class RegisterReq(BaseModel):
    account_id: str
    device_pubkey: str
    device_sig: str
    device_msg_version: str = "gmf:register:v1"

class RevokeReq(BaseModel):
    account_id: str
    device_pubkey: str

def _verify_register_sig(account_id: str, device_pubkey_hex: str, device_sig_hex: str) -> tuple[bool,str]:
    try:
        pk = bytes.fromhex(device_pubkey_hex.strip())
        sig = bytes.fromhex(device_sig_hex.strip())
        if len(pk)!=32 or len(sig)!=64:
            return (False, "bad_key_or_sig_len")
        msg = f"gmf:register:v1:{account_id}:{device_pubkey_hex.strip().lower()}".encode("utf-8")
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return (True, "ok")
    except InvalidSignature:
        return (False, "invalid_signature")
    except Exception:
        return (False, "bad_payload")

@router.post("/register")
def register(req: RegisterReq):
    ok, rs = _verify_register_sig(req.account_id, req.device_pubkey, req.device_sig)
    if not ok:
        return JSONResponse(status_code=400, content={"ok": False, "reason": rs})

    idx = load_devices_index()
    pk = req.device_pubkey.strip().lower()
    if pk in idx and idx[pk].get("revoked_at") is None:
        # already registered; ensure same account
        if idx[pk].get("account_id") != req.account_id:
            return JSONResponse(status_code=400, content={"ok": False, "reason": "device_already_bound_to_other_account"})
        return {"ok": True, "status": "already_registered"}

    append_device_event({"type":"register","ts":_now(),"account_id":req.account_id,"device_pubkey":pk})
    return {"ok": True, "status": "registered"}

@router.post("/revoke")
def revoke(req: RevokeReq):
    idx = load_devices_index()
    pk = req.device_pubkey.strip().lower()
    rec = idx.get(pk)
    if not rec:
        return JSONResponse(status_code=404, content={"ok": False, "reason": "device_not_found"})
    if rec.get("account_id") != req.account_id:
        return JSONResponse(status_code=400, content={"ok": False, "reason": "not_device_owner"})
    if rec.get("revoked_at") is not None:
        return {"ok": True, "status": "already_revoked"}
    append_device_event({"type":"revoke","ts":_now(),"account_id":req.account_id,"device_pubkey":pk})
    return {"ok": True, "status": "revoked"}

@router.get("/list/{account_id}")
def list_devices(account_id: str):
    idx = load_devices_index()
    out = [v for v in idx.values() if v.get("account_id")==account_id]
    return {"ok": True, "devices": out}
