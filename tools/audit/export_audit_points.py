#!/usr/bin/env python3
import json, sys
from pathlib import Path
from datetime import datetime, timezone

AUDIT_POINTS_MICRO = 50000  # 固定：每条 audit receipt 的“审计积分”

def main():
    if len(sys.argv) < 2:
        print("Usage: export_audit_points.py YYYY-MM-DD", file=sys.stderr)
        sys.exit(2)
    date = sys.argv[1]
    audit_path = Path("ledger/audit") / f"{date}.audit.jsonl"
    final_path = Path("ledger/snapshots") / f"{date}.final.json"
    out_dir = Path("releases/settlement") / date
    out_dir.mkdir(parents=True, exist_ok=True)

    if not final_path.exists():
        print("Missing final snapshot (required):", final_path, file=sys.stderr)
        sys.exit(2)
    if not audit_path.exists():
        # no audits: write empty export
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        out = {"generated_at": now, "date": date, "audit_points_micro_by_device_id": {}}
        (out_dir / "audit_points.json").write_text(json.dumps(out, indent=2) + "\n")
        print("Wrote empty:", out_dir / "audit_points.json")
        return

    points = {}
    total = 0
    parse_err = 0

    for ln in audit_path.read_text().splitlines():
        t = ln.strip()
        if not t:
            continue
        total += 1
        try:
            env = json.loads(t)
            payload = env.get("audit_payload", {})
            dev = payload.get("device_id")
            if isinstance(dev, str) and dev:
                points[dev] = points.get(dev, 0) + AUDIT_POINTS_MICRO
        except Exception:
            parse_err += 1

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = {
        "generated_at": now,
        "date": date,
        "audit_total": total,
        "audit_parse_errors": parse_err,
        "policy": f"audit_points_fixed_{AUDIT_POINTS_MICRO}_micro_per_attest",
        "audit_points_micro_by_device_id": points
    }
    (out_dir / "audit_points.json").write_text(json.dumps(out, indent=2) + "\n")
    print("Wrote:", out_dir / "audit_points.json")

if __name__ == "__main__":
    main()
