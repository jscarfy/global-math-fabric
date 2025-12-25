#!/usr/bin/env python3
import json, glob, hashlib
from pathlib import Path
from datetime import datetime, timezone

INBOX = Path("ledger/inbox")
OUT_DIR = Path("releases/leaderboard")
MAP = Path("ledger/identity/public_ids.json")

def load_map():
    if MAP.exists():
        try:
            return json.loads(MAP.read_text()).get("devices", {})
        except Exception:
            return {}
    return {}

def stable_public_id(device_id: str, salt: str) -> str:
    # deterministic pseudonym; change salt if you ever need to rotate
    return hashlib.sha256((salt + ":" + device_id).encode()).hexdigest()[:16]

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # aggregate credits per device_id
    credits = {}
    ssr_count = 0
    for fn in sorted(INBOX.glob("*.ssr.jsonl")):
        for line in fn.read_text().splitlines():
            if not line.strip():
                continue
            ssr = json.loads(line)
            payload = ssr.get("receipt_payload", {})
            dev = payload.get("device_id", "")
            delta = int(payload.get("credits_delta_micro", 0) or 0)
            if not dev:
                continue
            credits[dev] = credits.get(dev, 0) + delta
            ssr_count += 1

    # export (private)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    private_export = {
        "generated_at": now,
        "ssr_count": ssr_count,
        "credits_micro_by_device_id": credits
    }
    (OUT_DIR / "credits_export.json").write_text(json.dumps(private_export, indent=2) + "\n")

    # public leaderboard (optional anonymization + optional handles)
    devmap = load_map()
    salt = "gmf_public_v1"  # stable, keep it forever unless you want to rotate pseudonyms
    rows = []
    for dev, total in credits.items():
        m = devmap.get(dev, {})
        publish = bool(m.get("publish", False))
        handle = m.get("handle", "")
        pid = handle if (publish and handle) else stable_public_id(dev, salt)
        rows.append({"public_id": pid, "credits_micro": total})

    rows.sort(key=lambda r: r["credits_micro"], reverse=True)
    public = {
        "generated_at": now,
        "policy": "credits_policy_v2_deterministic",
        "entries": rows[:5000]  # cap to keep file bounded
    }
    (OUT_DIR / "public_leaderboard.json").write_text(json.dumps(public, indent=2) + "\n")

    print("Wrote:")
    print(" -", OUT_DIR / "credits_export.json")
    print(" -", OUT_DIR / "public_leaderboard.json")

if __name__ == "__main__":
    main()
