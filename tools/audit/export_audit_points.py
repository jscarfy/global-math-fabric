
#!/usr/bin/env python3
import json, sys, hashlib
from pathlib import Path
from datetime import datetime, timezone

AUDIT_POINTS_MICRO = 50000  # 固定：每條 audit receipt 的「審計積分」

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def main():
    if len(sys.argv) < 2:
        print("Usage: export_audit_points.py YYYY-MM-DD", file=sys.stderr)
        sys.exit(2)
    date = sys.argv[1]
    audit_log_path = Path("ledger/audit") / f"{date}.audit.jsonl"
    audit_final_path = Path("ledger/audit") / f"{date}.audit_final.json"
    final_path = Path("ledger/snapshots") / f"{date}.final.json"
    out_dir = Path("releases/settlement") / date
    out_dir.mkdir(parents=True, exist_ok=True)

    # 必須存在 final + audit_final（結算錨）
    if not final_path.exists():
        print("FATAL: missing final snapshot:", final_path, file=sys.stderr)
        sys.exit(2)
    if not audit_final_path.exists():
        print("FATAL: missing audit_final anchor:", audit_final_path, file=sys.stderr)
        sys.exit(2)
    if not audit_log_path.exists():
        # audit_final 存在但 audit_log 不在 => 本地資料不完整，拒絕
        print("FATAL: missing audit log file:", audit_log_path, file=sys.stderr)
        sys.exit(2)

    audit_final = json.loads(audit_final_path.read_text())
    payload = audit_final.get("audit_final_payload") or {}
    expected_log_sha = payload.get("audit_log_sha256")
    if not isinstance(expected_log_sha, str) or not expected_log_sha:
        print("FATAL: audit_final_payload.audit_log_sha256 missing", file=sys.stderr)
        sys.exit(2)

    audit_bytes = audit_log_path.read_bytes()
    got_log_sha = sha256_hex(audit_bytes)
    if got_log_sha != expected_log_sha:
        print("FATAL: audit log sha256 mismatch vs audit_final", file=sys.stderr)
        print(" expected:", expected_log_sha, file=sys.stderr)
        print(" got     :", got_log_sha, file=sys.stderr)
        sys.exit(2)

    # OK，開始計分（完全可重算、可審計）
    points = {}
    total = 0
    parse_err = 0

    for ln in audit_bytes.splitlines():
        t = ln.strip()
        if not t:
            continue
        total += 1
        try:
            env = json.loads(t.decode("utf-8"))
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
        "audit_anchor": {
            "audit_final_path": str(audit_final_path),
            "audit_log_path": str(audit_log_path),
            "audit_log_sha256": got_log_sha,
            "server_pubkey_b64": audit_final.get("server_pubkey_b64"),
            "server_sig_b64": audit_final.get("server_sig_b64"),
        },
        "audit_points_micro_by_device_id": points
    }
    (out_dir / "audit_points.json").write_text(json.dumps(out, indent=2) + "\n")
    print("Wrote:", out_dir / "audit_points.json")

if __name__ == "__main__":
    main()
