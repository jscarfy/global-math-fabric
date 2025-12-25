#!/usr/bin/env python3
import os, json, gzip, hashlib
from pathlib import Path
from datetime import datetime, timezone

RECEIPTS = Path(os.environ.get("GMF_LEDGER_RECEIPTS_PATH", "ledger/receipts/receipts.jsonl"))
OUT_PARTS = Path(os.environ.get("GMF_RECEIPTS_PARTS_DIR", "ledger/receipts/parts"))
OUT_MANIFESTS = Path(os.environ.get("GMF_RECEIPTS_MANIFESTS_DIR", "ledger/receipts/manifests"))

MAX_LINES_PER_PART = int(os.environ.get("GMF_PART_MAX_LINES", "200000"))   # tune
MAX_BYTES_PER_PART = int(os.environ.get("GMF_PART_MAX_BYTES", str(64*1024*1024)))  # 64MB gz target-ish

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def canon_json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def day_from_receipt_line(line: str) -> str:
    # receipts envelope: {"payload":{...,"ts_utc":...},...}
    try:
        env = json.loads(line)
        payload = env.get("payload", {})
        ts = payload.get("ts_utc") or payload.get("runtime", {}).get("ts") or env.get("ts_utc")
        if ts:
            # tolerate Z / +00:00
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        pass
    # fallback: today UTC
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")

def main():
    if not RECEIPTS.exists():
        print(json.dumps({"ok": False, "reason": "receipts_not_found", "path": str(RECEIPTS)}))
        return

    OUT_PARTS.mkdir(parents=True, exist_ok=True)
    OUT_MANIFESTS.mkdir(parents=True, exist_ok=True)

    # We partition whole file each run (MVP). Later you can do incremental partitioning.
    # Load lines grouped by day
    by_day = {}
    total_lines = 0

    with RECEIPTS.open("rt", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            d = day_from_receipt_line(line)
            by_day.setdefault(d, []).append(line)
            total_lines += 1

    written_days = []
    for d, lines in sorted(by_day.items()):
        day_dir = OUT_PARTS / d
        day_dir.mkdir(parents=True, exist_ok=True)

        parts = []
        part_idx = 0
        cur = []
        cur_lines = 0
        cur_bytes = 0

        def flush():
            nonlocal part_idx, cur, cur_lines, cur_bytes
            if not cur:
                return
            fn = day_dir / f"part-{part_idx:05d}.jsonl.gz"
            with gzip.open(fn, "wt", encoding="utf-8") as gz:
                for ln in cur:
                    gz.write(ln + "\n")
            info = {
                "file": str(fn.relative_to(Path("ledger"))),
                "sha256": sha256_file(fn),
                "lines": cur_lines,
            }
            parts.append(info)
            part_idx += 1
            cur, cur_lines, cur_bytes = [], 0, 0

        for ln in lines:
            b = len(ln.encode("utf-8")) + 1
            cur.append(ln)
            cur_lines += 1
            cur_bytes += b
            if cur_lines >= MAX_LINES_PER_PART or cur_bytes >= MAX_BYTES_PER_PART:
                flush()
        flush()

        manifest = {
            "kind": "gmf_receipts_manifest",
            "version": 1,
            "date_utc": d,
            "source_receipts_path": str(RECEIPTS),
            "part_rules": {"max_lines": MAX_LINES_PER_PART, "max_bytes": MAX_BYTES_PER_PART},
            "parts": parts,
            "total_lines": sum(p["lines"] for p in parts),
        }

        mp = OUT_MANIFESTS / f"{d}.manifest.json"
        mp.write_bytes(canon_json_bytes(manifest))
        mh = hashlib.sha256(canon_json_bytes(manifest)).hexdigest()
        # write also a .sha file for convenience
        (OUT_MANIFESTS / f"{d}.manifest.sha256").write_text(mh + "\n", encoding="utf-8")

        written_days.append({"day": d, "manifest": str(mp), "manifest_sha256": mh, "parts": len(parts)})

    print(json.dumps({"ok": True, "total_lines": total_lines, "days": written_days}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
