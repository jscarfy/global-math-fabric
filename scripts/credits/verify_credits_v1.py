import json, hashlib
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ZERO32 = b"\x00"*32

def sha256(b): return hashlib.sha256(b).digest()

def canon_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def main():
    receipts = Path("ledger/credits/receipts/receipts.jsonl")
    if not receipts.exists():
        raise SystemExit("no receipts.jsonl")

    # group by day
    by_day = {}
    with receipts.open("r", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            day = rec["receipt"]["day_utc"]
            by_day.setdefault(day, []).append(rec)

    for day, items in sorted(by_day.items()):
        h = ZERO32
        entries = 0
        for rec in items:
            receipt = rec["receipt"]
            receipt_sha = hashlib.sha256(canon_json(receipt)).hexdigest()
            assert receipt_sha == rec["receipt_sha256"], f"{day}: receipt_sha mismatch"

            pk = bytes.fromhex(receipt["server_pubkey_ed25519_hex"])
            sig = bytes.fromhex(rec["server_sig_ed25519_hex"])
            Ed25519PublicKey.from_public_bytes(pk).verify(sig, bytes.fromhex(receipt_sha))

            h = sha256(h + bytes.fromhex(receipt_sha))
            entries += 1

        root_file = Path("ledger/credits/daily_roots") / f"{day}.json"
        if root_file.exists():
            r = json.loads(root_file.read_text())
            assert int(r["entries"]) == entries, f"{day}: entries mismatch"
            assert r["root_hex"] == h.hex(), f"{day}: root mismatch"
        print(f"OK {day}: entries={entries} root={h.hex()}")

if __name__ == "__main__":
    main()
