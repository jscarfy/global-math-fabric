import json, os, time, secrets, hashlib
from typing import Dict, Any, Optional

ACCOUNTS_PATH = os.environ.get("GMF_ACCOUNTS_PATH", "ledger/accounts/accounts.jsonl")

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def append_account_event(evt: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(ACCOUNTS_PATH), exist_ok=True)
    with open(ACCOUNTS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(evt, ensure_ascii=False, separators=(",",":")) + "\n")

def load_accounts_index() -> Dict[str, Dict[str, Any]]:
    """
    Returns token -> account record
    Replay append-only jsonl.
    """
    idx: Dict[str, Dict[str, Any]] = {}
    if not os.path.exists(ACCOUNTS_PATH):
        return idx
    with open(ACCOUNTS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: 
                continue
            try:
                e=json.loads(line)
            except Exception:
                continue
            typ=e.get("type")
            tok=str(e.get("api_token",""))
            if not tok:
                continue
            if typ=="create":
                idx[tok]={
                    "account_id": str(e.get("account_id","")),
                    "api_token": tok,
                    "display_name": str(e.get("display_name","")),
                    "created_at": e.get("ts") or _now(),
                    "revoked_at": None,
                }
            elif typ=="revoke" and tok in idx:
                idx[tok]["revoked_at"] = e.get("ts") or _now()
            elif typ=="rotate" and tok in idx:
                # rotation event contains new_api_token
                new_tok=str(e.get("new_api_token",""))
                if new_tok:
                    rec=idx.pop(tok)
                    rec["api_token"]=new_tok
                    rec["revoked_at"]=None
                    idx[new_tok]=rec
    return idx

def create_account(display_name: str="") -> Dict[str, Any]:
    api_token = secrets.token_hex(32)  # 64 hex
    account_id = "acct_" + _sha256_hex(api_token)[:24]
    evt={"type":"create","ts":_now(),"account_id":account_id,"api_token":api_token,"display_name":display_name}
    append_account_event(evt)
    return {"account_id": account_id, "api_token": api_token, "display_name": display_name}

def revoke_token(api_token: str) -> None:
    append_account_event({"type":"revoke","ts":_now(),"api_token":api_token})

def rotate_token(api_token: str) -> Optional[Dict[str, Any]]:
    idx=load_accounts_index()
    rec=idx.get(api_token)
    if not rec or rec.get("revoked_at") is not None:
        return None
    new_tok = secrets.token_hex(32)
    append_account_event({"type":"rotate","ts":_now(),"api_token":api_token,"new_api_token":new_tok})
    return {"account_id": rec["account_id"], "api_token": new_tok, "display_name": rec.get("display_name","")}
