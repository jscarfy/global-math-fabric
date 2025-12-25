from fastapi import Header
from fastapi.responses import JSONResponse
from typing import Optional, Tuple, Dict, Any
from app.accounts.store import load_accounts_index

def require_account(authorization: Optional[str]=Header(default=None)) -> Tuple[Optional[Dict[str,Any]], Optional[JSONResponse]]:
    if not authorization or not authorization.startswith("Bearer "):
        return None, JSONResponse(status_code=401, content={"ok": False, "reason": "missing_bearer_token"})
    tok = authorization[len("Bearer "):].strip()
    idx = load_accounts_index()
    rec = idx.get(tok)
    if not rec or rec.get("revoked_at") is not None:
        return None, JSONResponse(status_code=401, content={"ok": False, "reason": "invalid_or_revoked_token"})
    return rec, None
