import json, os, time
from typing import Optional, Dict, Any

DEVICES_PATH = os.environ.get("GMF_DEVICES_PATH", "ledger/devices/devices.jsonl")

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def append_device_event(evt: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(DEVICES_PATH), exist_ok=True)
    with open(DEVICES_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(evt, ensure_ascii=False, separators=(",",":")) + "\n")

def load_devices_index() -> Dict[str, Dict[str, Any]]:
    """
    Returns map device_pubkey_hex -> record {account_id, created_at, revoked_at?}
    Derived by replaying jsonl (append-only).
    """
    idx: Dict[str, Dict[str, Any]] = {}
    if not os.path.exists(DEVICES_PATH):
        return idx
    with open(DEVICES_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            try:
                e=json.loads(line)
            except Exception:
                continue
            typ=e.get("type")
            pk=str(e.get("device_pubkey","")).lower()
            if len(pk)!=64:
                continue
            if typ=="register":
                idx[pk] = {
                    "device_pubkey": pk,
                    "account_id": str(e.get("account_id","")),
                    "created_at": e.get("ts") or _now(),
                    "revoked_at": None,
                }
            elif typ=="revoke" and pk in idx:
                idx[pk]["revoked_at"] = e.get("ts") or _now()
    return idx

def get_device(pk_hex: str) -> Optional[Dict[str, Any]]:
    pk_hex = pk_hex.strip().lower()
    return load_devices_index().get(pk_hex)
