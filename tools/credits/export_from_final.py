#!/usr/bin/env python3
import json, hashlib, sys
from pathlib import Path
from datetime import datetime, timezone

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def load_json(path: Path):
    return json.loads(path.read_text())

def main():
    if len(sys.argv) < 2:
        print("Usage: export_from_final.py YYYY-MM-DD", file=sys.stderr)
        sys.exit(2)
    date = sys.argv[1]

    final_path = Path("ledger/snapshots") / f"{date}.final.json"
    inbox_path = Path("ledger/inbox") / f"{date}.ssr.jsonl"
    out_dir = Path("releases/settlement") / date
    out_dir.mkdir(parents=True, exist_ok=True)

    if not final_path.exists():
        print(f"Missing final snapshot: {final_path}", file=sys.stderr)
        sys.exit(2)
    if not inbox_path.exists():
        print(f"Missing inbox ledger: {inbox_path}", file=sys.stderr)
        sys.exit(2)

    final = load_json(final_path)
    payload = final.get("final_payload") or {}
    expected_sha = payload.get("ssr_sha256")
    if not expected_sha or not isinstance(expected_sha, str):
        print("final_payload.ssr_sha256 missing", file=sys.stderr)
        sys.exit(2)

    inbox_bytes = inbox_path.read_bytes()
    got_sha = sha256_hex(inbox_bytes)
    if got_sha != expected_sha:
        print("FATAL: inbox sha256 mismatch vs final snapshot", file=sys.stderr)
        print(" expected:", expected_sha, file=sys.stderr)
        print(" got     :", got_sha, file=sys.stderr)
        sys.exit(2)

    # Aggregate credits (authoritative data is SSR receipt_payload)
    credits = {}
    ssr_total = 0
    parse_err = 0

    for line in inbox_bytes.splitlines():
        if not line.strip():
            continue
        ssr_total += 1
        try:
            obj = json.loads(line.decode("utf-8"))
            rp = obj.get("receipt_payload", {})
            dev = rp.get("device_id")
            delta = int(rp.get("credits_delta_micro") or 0)
            if isinstance(dev, str) and dev:
                credits[dev] = credits.get(dev, 0) + delta
        except Exception:
            parse_err += 1

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Export (private)
    credits_export = {
        "generated_at": now,
        "date": date,
        "policy_id": payload.get("policy", "credits_policy_v2_deterministic"),
        "ssr_total": ssr_total,
        "ssr_parse_errors": parse_err,
        "final_anchor": {
            "final_path": str(final_path),
            "inbox_path": str(inbox_path),
            "final_payload": payload,
            "server_pubkey_b64": final.get("server_pubkey_b64"),
            "server_sig_b64": final.get("server_sig_b64"),
            "inbox_sha256": got_sha
        },
        "credits_micro_by_device_id": credits
    }
    (out_dir / "credits_export.json").write_text(json.dumps(credits_export, indent=2) + "\n")

    # Public leaderboard (anonymize deterministically)
    salt = "gmf_public_v1"
    def pseudonym(device_id: str) -> str:
        return hashlib.sha256((salt + ":" + device_id).encode()).hexdigest()[:16]

    rows = [{"public_id": pseudonym(dev), "credits_micro": total} for dev, total in credits.items()]
    rows.sort(key=lambda r: r["credits_micro"], reverse=True)

    leaderboard = {
        "generated_at": now,
        "date": date,
        "policy_id": credits_export["policy_id"],
        "final_anchor": {
            "ssr_sha256": payload.get("ssr_sha256"),
            "server_pubkey_b64": final.get("server_pubkey_b64"),
            "server_sig_b64": final.get("server_sig_b64"),
        },
        "entries": rows[:5000]
    }
    (out_dir / "public_leaderboard.json").write_text(json.dumps(leaderboard, indent=2) + "\n")

    print("Wrote:")
    print(" -", out_dir / "credits_export.json")
    print(" -", out_dir / "public_leaderboard.json")

if __name__ == "__main__":
    main()
