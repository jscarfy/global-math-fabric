import os, json, time
from typing import Dict, Any

RECEIPTS_DIR = os.environ.get("GMF_RECEIPTS_DIR", "ledger/receipts")

def _day_utc(ts_iso: str) -> str:
    # expects "YYYY-MM-DD..." (we only need day prefix)
    s = (ts_iso or "").strip()
    return s[:10] if len(s) >= 10 else time.strftime("%Y-%m-%d", time.gmtime())

def append_partitioned_receipt(receipt: Dict[str, Any]) -> None:
    acct = str((receipt.get("account") or {}).get("account_id","unknown")).strip()
    ts = str(receipt.get("ts") or receipt.get("issued_at") or "")
    day = _day_utc(ts)
    od = os.path.join(RECEIPTS_DIR, acct)
    os.makedirs(od, exist_ok=True)
    path = os.path.join(od, f"{day}.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(receipt, ensure_ascii=False, separators=(",",":")) + "\n")
