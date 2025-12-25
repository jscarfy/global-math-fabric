from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .store import issue, load_index

router = APIRouter(prefix="/api/invite", tags=["invite"])

class IssueReq(BaseModel):
    n: int = 1
    admin_secret: str = ""

@router.post("/issue")
def issue_codes(req: IssueReq):
    # ultra-minimal admin gate by env secret
    import os
    sec=os.environ.get("GMF_INVITE_ADMIN_SECRET","")
    if sec and req.admin_secret != sec:
        return JSONResponse(status_code=403, content={"ok": False, "reason": "bad_admin_secret"})
    codes=issue(max(1,min(req.n,1000)))
    return {"ok": True, "codes": codes}

@router.get("/status/{code}")
def status(code: str):
    idx=load_index()
    rec=idx.get(code)
    if not rec:
        return JSONResponse(status_code=404, content={"ok": False, "reason": "not_found"})
    return {"ok": True, **rec}
