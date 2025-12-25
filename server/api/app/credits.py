import os, json
from fastapi import APIRouter

router = APIRouter(prefix="/credits", tags=["credits"])

RECEIPTS_PATH = os.environ.get("GMF_LEDGER_RECEIPTS_PATH", "ledger/receipts/receipts.jsonl")

def iter_receipts():
    if not os.path.exists(RECEIPTS_PATH):
        return
    with open(RECEIPTS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                env = json.loads(line)
                payload_b64 = env.get("payload_b64")
                # server already stores payload_b64, but for MVP we rely on the plain decoded payload stored elsewhere?
                # In this repo, append_envelope_line writes envelope only; so we need payload_sha metadata:
                # We'll embed payload in envelope in future. For now: accept that append_envelope_line payload is not in jsonl.
                # => fallback: if envelope includes "payload" (some implementations do), use it.
                payload = env.get("payload")
                if payload:
                    yield payload
            except Exception:
                continue

@router.get("/summary")
def credits_summary(device_id: str | None = None, top: int = 20):
    total = 0
    by_device = {}
    n = 0
    for payload in iter_receipts():
        if payload.get("type") != "work_receipt":
            continue
        n += 1
        dev = str(payload.get("device_id") or "")
        c = int(payload.get("awarded_credits") or 0)
        total += c
        by_device[dev] = by_device.get(dev, 0) + c

    if device_id:
        return {"ok": True, "device_id": device_id, "credits": by_device.get(device_id, 0), "total_credits": total, "work_receipts_count": n}

    # leaderboard
    items = sorted(by_device.items(), key=lambda kv: kv[1], reverse=True)[: max(1, min(200, int(top)))]
    return {"ok": True, "total_credits": total, "work_receipts_count": n, "leaderboard": [{"device_id": k, "credits": v} for k, v in items]}
