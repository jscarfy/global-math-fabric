from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .store import create_account, rotate_token, revoke_token
from app.auth.bearer import require_account

router = APIRouter(prefix="/api/account", tags=["account"])

class CreateReq(BaseModel):
    display_name: str = ""

@router.post("/create")
def create(req: CreateReq):
    out = create_account(display_name=req.display_name)
    return {"ok": True, **out}

@router.get("/me")
def me(authorization: str | None = None):
    rec, err = require_account(authorization)
    if err: return err
    return {"ok": True, "account_id": rec["account_id"], "display_name": rec.get("display_name","")}

@router.post("/rotate_token")
def rotate(authorization: str | None = None):
    rec, err = require_account(authorization)
    if err: return err
    out = rotate_token(rec["api_token"])
    if not out:
        return JSONResponse(status_code=400, content={"ok": False, "reason": "cannot_rotate"})
    return {"ok": True, **out}

@router.post("/revoke_token")
def revoke(authorization: str | None = None):
    rec, err = require_account(authorization)
    if err: return err
    revoke_token(rec["api_token"])
    return {"ok": True, "status": "revoked"}
