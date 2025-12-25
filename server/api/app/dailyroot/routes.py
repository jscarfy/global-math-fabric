import os, glob
from fastapi import APIRouter
from fastapi.responses import JSONResponse, Response

DAILY_ROOTS_DIR = os.environ.get("GMF_DAILY_ROOTS_DIR", "ledger/daily_roots")

router = APIRouter(prefix="/api/daily_root", tags=["daily_root"])

@router.get("/{day}")
def get_daily_root(day: str):
    cands = glob.glob(os.path.join(DAILY_ROOTS_DIR, "**", f"*{day}*.json"), recursive=True)
    if not cands:
        return JSONResponse(status_code=404, content={"ok": False, "reason": "daily_root_not_found"})
    cands = sorted(cands, key=lambda p: os.path.getsize(p), reverse=True)
    target = cands[0]
    return Response(content=open(target, "rb").read(), media_type="application/json")
