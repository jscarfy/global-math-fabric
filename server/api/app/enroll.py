import os, json, time, hmac, hashlib, base64
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel

router = APIRouter(prefix="/enroll", tags=["enroll"])

def _b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def _b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))

def _hmac(secret: bytes, msg: bytes) -> bytes:
    return hmac.new(secret, msg, hashlib.sha256).digest()

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _secret() -> bytes:
    sec = os.environ.get("GMF_ENROLL_SECRET", "")
    if not sec:
        raise RuntimeError("GMF_ENROLL_SECRET missing")
    return sec.encode("utf-8")

def _admin_ok(admin_token: str | None) -> None:
    need = os.environ.get("GMF_ADMIN_TOKEN", "")
    if need and (admin_token != need):
        raise HTTPException(status_code=403, detail="admin_forbidden")

class MintReq(BaseModel):
    api: str
    topics: str = ""
    policy_version: str = "v1"
    daily_credit_limit: int = 0      # 0 unlimited
    expires_in_days: int = 36500     # ~100y default; set 0 for no exp

@router.post("/mint")
def mint(req: MintReq, x_gmf_admin: str | None = Header(default=None)):
    """
    Operator-only. Returns token + QR uri.
    Protect with GMF_ADMIN_TOKEN (optional). If GMF_ADMIN_TOKEN is empty, endpoint is open (not recommended).
    """
    _admin_ok(x_gmf_admin)

    now = int(time.time())
    exp = 0
    if int(req.expires_in_days) > 0:
        exp = now + int(req.expires_in_days) * 86400

    payload = {
        "api": req.api,
        "topics": req.topics,
        "policy_version": req.policy_version,
        "daily_credit_limit": int(req.daily_credit_limit),
        "iat": now,
        "exp": exp,
        "nonce": os.urandom(12).hex(),
    }
    header = {"alg": "HS256", "typ": "GMF-ENROLL", "v": 1}

    h = _b64u_enc(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    p = _b64u_enc(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig = _b64u_enc(_hmac(_secret(), f"{h}.{p}".encode("utf-8")))
    token = f"{h}.{p}.{sig}"
    enroll_ref = _sha256_hex(token)

    # gmf://enroll?token=...
    qr_uri = f"gmf://enroll?token={token}"
    return {"ok": True, "token": token, "enroll_ref": enroll_ref, "qr_uri": qr_uri, "payload": payload}

def verify(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("bad token parts")
        h, p, sig = parts
        want = _b64u_enc(_hmac(_secret(), f"{h}.{p}".encode("utf-8")))
        if not hmac.compare_digest(want, sig):
            raise ValueError("bad signature")
        header = json.loads(_b64u_dec(h).decode("utf-8"))
        payload = json.loads(_b64u_dec(p).decode("utf-8"))
        if header.get("typ") != "GMF-ENROLL":
            raise ValueError("bad typ")
        exp = int(payload.get("exp") or 0)
        if exp and int(time.time()) > exp:
            raise ValueError("expired")
        return payload
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"enroll_token_invalid:{e}")
