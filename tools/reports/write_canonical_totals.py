#!/usr/bin/env python3
import json, sys, hashlib
from pathlib import Path
from datetime import datetime, timezone

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def try_sum_main_credits(settle_dir: Path):
    # heuristic: scan json files for a key that looks like credits map
    candidates = []
    for p in sorted(settle_dir.glob("*.json")):
        if p.name in ("audit_points.json", "canonical_totals.json"):
            continue
        try:
            v = json.loads(p.read_text())
        except Exception:
            continue

        # try common shapes
        for k in ("credits_micro_by_device_id","credits_by_device_id","credits_micro_by_device","main_credits_micro_by_device_id"):
            m = v.get(k) if isinstance(v, dict) else None
            if isinstance(m, dict) and m and all(isinstance(x,(int,float)) for x in m.values()):
                total = int(sum(int(x) for x in m.values()))
                candidates.append((p.name, k, total))
        # top-level dict of device->int (rare but possible)
        if isinstance(v, dict) and v and all(isinstance(x,(int,float)) for x in v.values()):
            total = int(sum(int(x) for x in v.values()))
            candidates.append((p.name, "<top_level_map>", total))

    if not candidates:
        return None, []

    # pick max total candidate (usually the right one)
    candidates.sort(key=lambda t: t[2], reverse=True)
    chosen = candidates[0]
    return chosen[2], candidates

def sum_audit_points(settle_dir: Path):
    p = settle_dir / "audit_points.json"
    if not p.exists():
        return None
    v = json.loads(p.read_text())
    mp = v.get("audit_points_micro_by_device_id", {})
    if isinstance(mp, dict):
        return int(sum(int(x) for x in mp.values() if isinstance(x,(int,float))))
    return None

def main():
    if len(sys.argv) < 2:
        print("Usage: write_canonical_totals.py YYYY-MM-DD", file=sys.stderr)
        sys.exit(2)
    date = sys.argv[1]
    settle_dir = Path("releases/settlement") / date
    settle_dir.mkdir(parents=True, exist_ok=True)

    main_total, candidates = try_sum_main_credits(settle_dir)
    audit_total = sum_audit_points(settle_dir)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # hash sources for auditability
    src_hashes = {}
    for p in sorted(settle_dir.glob("*.json")):
        if p.name == "canonical_totals.json":
            continue
        try:
            b = p.read_bytes()
            src_hashes[p.name] = sha256_hex(b)
        except Exception:
            pass

    out = {
        "generated_at": now,
        "date": date,
        "main_credits_total_micro": main_total,
        "audit_points_total_micro": audit_total,
        "main_credits_detection_candidates": candidates,
        "source_file_sha256": src_hashes
    }

    (settle_dir / "canonical_totals.json").write_text(json.dumps(out, indent=2) + "\n")
    print("Wrote:", settle_dir / "canonical_totals.json")

if __name__ == "__main__":
    main()
