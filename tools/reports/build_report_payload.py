#!/usr/bin/env python3
import json, sys, hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta

def canon(obj):
    if isinstance(obj, dict):
        return {k: canon(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [canon(x) for x in obj]
    return obj

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def load_json(p: Path):
    return json.loads(p.read_text())

def require_file(p: Path, msg: str):
    if not p.exists():
        raise SystemExit(f"FATAL: {msg}: {p}")

def triple_ok_for_date(d: str) -> bool:
    f = Path("ledger/snapshots") / f"{d}.final.json"
    a = Path("ledger/audit") / f"{d}.audit_final.json"
    m = Path("ledger/meta_audit") / f"{d}.meta_audit_final.json"
    return f.exists() and a.exists() and m.exists()

def extract_bindings(d: str):
    final_env = load_json(Path("ledger/snapshots") / f"{d}.final.json")
    audit_final = load_json(Path("ledger/audit") / f"{d}.audit_final.json")
    meta_final = load_json(Path("ledger/meta_audit") / f"{d}.meta_audit_final.json")

    final_ssr = final_env["final_payload"]["ssr_sha256"]
    audit_log_sha = audit_final["audit_final_payload"]["audit_log_sha256"]
    meta_log_sha = meta_final["meta_audit_final_payload"]["meta_audit_log_sha256"]
    return final_ssr, audit_log_sha, meta_log_sha

def dates_in_month(ym: str):
    y,m = map(int, ym.split("-"))
    start = datetime(y, m, 1, tzinfo=timezone.utc)
    if m == 12:
        end = datetime(y+1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(y, m+1, 1, tzinfo=timezone.utc)
    cur = start
    out=[]
    while cur < end:
        out.append(cur.strftime("%Y-%m-%d"))
        cur += timedelta(days=1)
    return out

def dates_in_year(y: str):
    y=int(y)
    start = datetime(y,1,1,tzinfo=timezone.utc)
    end = datetime(y+1,1,1,tzinfo=timezone.utc)
    cur=start
    out=[]
    while cur<end:
        out.append(cur.strftime("%Y-%m-%d"))
        cur += timedelta(days=1)
    return out

def main():
    if len(sys.argv) < 3:
        print("Usage: build_report_payload.py monthly YYYY-MM  |  build_report_payload.py yearly YYYY", file=sys.stderr)
        sys.exit(2)
    kind = sys.argv[1]
    pid = sys.argv[2]

    if kind == "monthly":
        candidates = dates_in_month(pid)
    elif kind == "yearly":
        candidates = dates_in_year(pid)
    else:
        raise SystemExit("bad kind")

    included=[]
    excluded=[]
    finals=[]
    audits=[]
    metas=[]

    for d in candidates:
        if triple_ok_for_date(d):
            try:
                fs, al, ml = extract_bindings(d)
                included.append(d)
                finals.append(fs)
                audits.append(al)
                metas.append(ml)
            except Exception:
                excluded.append(d)
        else:
            excluded.append(d)

    bindings = {
        "daily_final_ssr_sha256_list": finals,
        "daily_audit_log_sha256_list": audits,
        "daily_meta_audit_log_sha256_list": metas
    }
    roll_src = {"included_dates": included, "bindings": bindings}
    roll_bytes = json.dumps(canon(roll_src), separators=(",",":"), ensure_ascii=False).encode("utf-8")
    roll_sha = sha256_hex(roll_bytes)

    payload = {
        "kind": kind,
        "period_id": pid,
        "generated_at_unix_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "included_dates": included,
        "excluded_dates": excluded,
        "aggregates": {
            "days_count": len(included),
            "sum_main_credits_micro": None,
            "sum_audit_points_micro": None
        },
        "bindings": bindings,
        "merkle_or_rollup": {
            "rollup_sha256": roll_sha,
            "method": "sha256_canon_v1"
        }
    }
    print(json.dumps(payload, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
