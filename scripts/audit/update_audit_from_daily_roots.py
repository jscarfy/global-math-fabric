#!/usr/bin/env python3
import os, json, hashlib
from pathlib import Path
from datetime import datetime, timezone

ROOT_DIR = Path(os.environ.get("GMF_DAILY_ROOTS_DIR", "ledger/daily_roots"))
AUDIT_DIR = Path(os.environ.get("GMF_AUDIT_DIR", "ledger/audit"))
STATE = AUDIT_DIR / "state_daily_root_chain.json"
GENESIS = os.environ.get("GMF_AUDIT_GENESIS", "GMF_AUDIT_GENESIS_v3_DAILY_ROOT").encode("utf-8")

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def hex_(b: bytes) -> str:
    return b.hex()

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def load_state():
    if STATE.exists():
        return json.loads(STATE.read_text(encoding="utf-8"))
    return {"version": 1, "last_day": "", "day_count": 0, "head_hash": hex_(sha256(GENESIS)), "updated_at": None}

def save_state(st):
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")

def list_days():
    days=[]
    for p in ROOT_DIR.glob("*.root.json"):
        days.append(p.name.replace(".root.json",""))
    return sorted(set(days))

def root_sha(day: str) -> str:
    p = ROOT_DIR / f"{day}.root.json"
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    st = load_state()
    prev = bytes.fromhex(st["head_hash"])
    last = st.get("last_day") or ""
    added=0

    for d in list_days():
        if last and d <= last: continue
        rh = root_sha(d)
        prev = sha256(prev + f"{d}|{rh}".encode("utf-8"))
        st["last_day"]=d
        st["day_count"]=int(st.get("day_count",0))+1
        added += 1

    st["head_hash"]=hex_(prev)
    st["updated_at"]=now_iso()
    save_state(st)

    cp = {
        "kind":"gmf_audit_checkpoint_daily_root_chain",
        "version":1,
        "date_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "generated_at_utc": now_iso(),
        "chain":{"alg":"sha256","genesis":GENESIS.decode(errors="replace"),
                "head_hash_hex":st["head_hash"],"last_day":st["last_day"],"day_count":st["day_count"],
                "step_rule":"H=sha256(H_prev || f'{day}|sha256(day.root.json)')"},
    }
    (AUDIT_DIR/"latest_daily_root_chain.json").write_text(json.dumps(cp,ensure_ascii=False,indent=2),encoding="utf-8")

    print(json.dumps({"ok":True,"added_days":added,"state":st},ensure_ascii=False,indent=2))

if __name__=="__main__":
    main()
