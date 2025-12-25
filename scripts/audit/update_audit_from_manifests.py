#!/usr/bin/env python3
import os, json, hashlib
from pathlib import Path
from datetime import datetime, timezone

MANIFESTS_DIR = Path(os.environ.get("GMF_RECEIPTS_MANIFESTS_DIR", "ledger/receipts/manifests"))
AUDIT_DIR = Path(os.environ.get("GMF_AUDIT_DIR", "ledger/audit"))
STATE = AUDIT_DIR / "state_manifest_chain.json"
CHECKPOINTS = AUDIT_DIR / "checkpoints"
GENESIS = os.environ.get("GMF_AUDIT_GENESIS", "GMF_AUDIT_GENESIS_v2_MANIFEST").encode("utf-8")

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def hex_(b: bytes) -> str:
    return b.hex()

def canon_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def load_state():
    if STATE.exists():
        return json.loads(STATE.read_text(encoding="utf-8"))
    return {
        "version": 1,
        "manifests_dir": str(MANIFESTS_DIR),
        "last_day": "",        # last processed YYYY-MM-DD
        "day_count": 0,
        "head_hash": hex_(sha256(GENESIS)),
        "updated_at": None,
    }

def save_state(st):
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")

def list_days():
    days = []
    for p in MANIFESTS_DIR.glob("*.manifest.json"):
        name = p.name.replace(".manifest.json", "")
        days.append(name)
    return sorted(set(days))

def load_manifest_sha(day: str) -> str:
    mp = MANIFESTS_DIR / f"{day}.manifest.json"
    if not mp.exists():
        raise FileNotFoundError(mp)
    h = hashlib.sha256(mp.read_bytes()).hexdigest()
    return h

def update_chain(st):
    days = list_days()
    last = st.get("last_day") or ""
    prev = bytes.fromhex(st["head_hash"])
    added = 0

    for d in days:
        if last and d <= last:
            continue
        mh = load_manifest_sha(d)
        # step: H_{n+1} = sha256( H_n || day || manifest_sha )
        msg = f"{d}|{mh}".encode("utf-8")
        prev = sha256(prev + msg)
        st["last_day"] = d
        st["day_count"] = int(st.get("day_count", 0)) + 1
        added += 1

    st["head_hash"] = hex_(prev)
    st["updated_at"] = now_iso()
    return st, added

def write_checkpoint(st):
    CHECKPOINTS.mkdir(parents=True, exist_ok=True)
    d = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cp_path = CHECKPOINTS / f"{d}.manifest_chain.json"

    cp = {
        "kind": "gmf_audit_checkpoint_manifest_chain",
        "version": 1,
        "date_utc": d,
        "generated_at_utc": now_iso(),
        "manifests_dir": str(MANIFESTS_DIR),
        "chain": {
            "alg": "sha256",
            "genesis": GENESIS.decode("utf-8", errors="replace"),
            "head_hash_hex": st["head_hash"],
            "last_day": st["last_day"],
            "day_count": st["day_count"],
            "step_rule": "H = sha256(H_prev || f'{day}|{sha256(manifest.json)}')",
        },
    }

    cp_path.write_bytes(canon_bytes(cp))
    (AUDIT_DIR / "latest_manifest_chain.json").write_bytes(canon_bytes(cp))
    return cp_path

def main():
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    st = load_state()
    st, added = update_chain(st)
    save_state(st)
    cp = write_checkpoint(st)
    print(json.dumps({"ok": True, "added_days": added, "state": st, "checkpoint": str(cp)}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
