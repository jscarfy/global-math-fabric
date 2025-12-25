from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/antisybil", tags=["antisybil"])

@router.get("/status")
def status():
    return {
        "ok": True,
        "webauthn": "not_implemented",
        "reputation": "not_implemented",
        "note": "plugins are optional; base ledger remains auditable"
    }

@router.post("/webauthn/begin")
def webauthn_begin():
    return JSONResponse(status_code=501, content={"ok": False, "reason": "not_implemented"})

@router.post("/webauthn/finish")
def webauthn_finish():
    return JSONResponse(status_code=501, content={"ok": False, "reason": "not_implemented"})

@router.get("/reputation/{account_id}")
def reputation(account_id: str):
    return JSONResponse(status_code=501, content={"ok": False, "reason": "not_implemented"})
