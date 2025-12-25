from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .store import create_account, rotate_token, revoke_token
from app.invites.store import consume
from app.auth.bearer import require_account

router = APIRouter(prefix="/api/account", tags=["account"])

class CreateReq(BaseModel):
    display_name: str = ""
    invite_code: str = ""

@router.post("/create")
def create(req: CreateReq):
    import os
    if os.environ.get('GMF_INVITE_REQUIRED','0') == '1':
        if not req.invite_code:
            return JSONResponse(status_code=400, content={'ok': False, 'reason': 'invite_required'})

    out = create_account(display_name=req.display_name)
    if os.environ.get('GMF_INVITE_REQUIRED','0') == '1':
        if not consume(req.invite_code, out['account_id']):
            return JSONResponse(status_code=400, content={'ok': False, 'reason': 'bad_or_used_invite'})
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
