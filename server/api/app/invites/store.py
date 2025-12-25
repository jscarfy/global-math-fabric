import json, os, time, secrets
from typing import Dict, Any, Optional

INVITES_PATH = os.environ.get("GMF_INVITES_PATH", "ledger/invites/invites.jsonl")

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def append(evt: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(INVITES_PATH), exist_ok=True)
    with open(INVITES_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(evt, ensure_ascii=False, separators=(",",":"))+"\n")

def load_index() -> Dict[str, Dict[str, Any]]:
    idx={}
    if not os.path.exists(INVITES_PATH):
        return idx
    with open(INVITES_PATH,"r",encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            e=json.loads(line)
            code=str(e.get("code",""))
            if not code: continue
            if e.get("type")=="issue":
                idx[code]={"code":code,"issued_at":e.get("ts"),"used_at":None,"used_by":None}
            elif e.get("type")=="use" and code in idx:
                idx[code]["used_at"]=e.get("ts")
                idx[code]["used_by"]=e.get("account_id")
    return idx

def issue(n: int=1) -> list[str]:
    out=[]
    for _ in range(n):
        code="inv_"+secrets.token_hex(8)
        append({"type":"issue","ts":_now(),"code":code})
        out.append(code)
    return out

def consume(code: str, account_id: str) -> bool:
    idx=load_index()
    rec=idx.get(code)
    if not rec: return False
    if rec.get("used_at") is not None: return False
    append({"type":"use","ts":_now(),"code":code,"account_id":account_id})
    return True
