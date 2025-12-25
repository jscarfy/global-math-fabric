import os, json, hashlib
from datetime import datetime, timezone, date
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

LEDGER_DIR = Path(os.environ.get("GMF_CREDITS_LEDGER_DIR", "ledger/credits"))
RECEIPTS_PATH = LEDGER_DIR / "receipts" / "receipts.jsonl"
DAILY_ROOTS_DIR = LEDGER_DIR / "daily_roots"
KEY_DIR = Path(os.environ.get("GMF_SERVER_KEY_DIR", "server/keys"))
SK_PATH = KEY_DIR / "credits_ed25519_sk.hex"
PK_PATH = KEY_DIR / "credits_ed25519_pk.hex"

ZERO32 = "00" * 32

def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _canon_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _load_or_create_keys():
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if SK_PATH.exists() and PK_PATH.exists():
        sk = bytes.fromhex(SK_PATH.read_text().strip())
        pk = bytes.fromhex(PK_PATH.read_text().strip())
        return sk, pk

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    sk = priv.private_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.PrivateFormat.Raw,
        encryption_algorithm=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.NoEncryption(),
    )
    pk = pub.public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.PublicFormat.Raw,
    )
    SK_PATH.write_text(sk.hex())
    PK_PATH.write_text(pk.hex())
    return sk, pk

def _sign(sk_raw: bytes, msg32_hex: str) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(sk_raw)
    sig = priv.sign(bytes.fromhex(msg32_hex))
    return sig.hex()

def _today_utc() -> str:
    return datetime.now(timezone.utc).date().isoformat()

def _ts_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def _read_prev_entry_hash_for_day(day_utc: str) -> str:
    # scan last line of receipts.jsonl for same day; if none => ZERO32
    if not RECEIPTS_PATH.exists():
        return ZERO32
    last = None
    with RECEIPTS_PATH.open("rb") as f:
        for line in f:
            try:
                rec = json.loads(line.decode("utf-8"))
                if rec.get("receipt", {}).get("day_utc") == day_utc:
                    last = rec
            except Exception:
                continue
    if not last:
        return ZERO32
    # daily chaining uses prev_entry_hash stored inside receipt
    # we can reconstruct current entry_hash and use it as prev for next
    prev_entry = last["receipt"]["prev_entry_hash"]
    cur_entry_hash = _sha256_hex(bytes.fromhex(prev_entry) + bytes.fromhex(last["receipt_sha256"]))
    return cur_entry_hash

def _read_prev_day_root(day_utc: str) -> str:
    # previous day file if exists
    d = date.fromisoformat(day_utc)
    prev = (d.fromordinal(d.toordinal() - 1)).isoformat()
    p = DAILY_ROOTS_DIR / f"{prev}.json"
    if p.exists():
        try:
            j = json.loads(p.read_text())
            return j.get("root_hex", ZERO32)
        except Exception:
            return ZERO32
    return ZERO32

def _write_daily_root(day_utc: str):
    DAILY_ROOTS_DIR.mkdir(parents=True, exist_ok=True)
    prev_day_root = _read_prev_day_root(day_utc)
    # recompute chain by scanning all entries for that day
    entries = 0
    h = bytes.fromhex(ZERO32)
    if RECEIPTS_PATH.exists():
        with RECEIPTS_PATH.open("rb") as f:
            for line in f:
                try:
                    rec = json.loads(line.decode("utf-8"))
                    if rec.get("receipt", {}).get("day_utc") != day_utc:
                        continue
                    entries += 1
                    h = hashlib.sha256(h + bytes.fromhex(rec["receipt_sha256"])).digest()
                except Exception:
                    continue

    out = {
        "kind":"gmf_credit_daily_root_v1",
        "day_utc": day_utc,
        "prev_day_root_hex": prev_day_root,
        "entries": entries,
        "root_hex": h.hex()
    }
    (DAILY_ROOTS_DIR / f"{day_utc}.json").write_text(json.dumps(out, sort_keys=True, indent=2))

def record_receipt_v1(
    *,
    policy_hash: str,
    verifier_name: str,
    verifier_version: str,
    verifier_digest_sha256: str,
    job_id: str,
    lease_id: str,
    job_kind: str,
    job_input_json: str,
    job_output_json: str,
    device_pk_ed25519: str,
    device_sig_over_submit_sha256: str,
    audit_rate: float,
    audit_chunk_size: int,
    audit_sample_idx0_included: bool,
    awarded_credits: int,
):
    LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    (LEDGER_DIR / "receipts").mkdir(parents=True, exist_ok=True)

    sk, pk = _load_or_create_keys()
    day_utc = _today_utc()

    input_sha = _sha256_hex(job_input_json.encode("utf-8"))
    output_sha = _sha256_hex(job_output_json.encode("utf-8"))
    prev_entry_hash = _read_prev_entry_hash_for_day(day_utc)

    receipt = {
        "kind":"gmf_credit_receipt_v1",
        "ts_utc": _ts_utc(),
        "day_utc": day_utc,
        "server_pubkey_ed25519_hex": pk.hex(),
        "policy_hash": policy_hash,
        "verifier": {"name": verifier_name, "version": verifier_version, "digest_sha256": verifier_digest_sha256}
    # also store in per-account/day partitions
    try:
        append_partitioned_receipt(receipt)
    except Exception:
        pass
,
        "job": {"job_id": job_id, "lease_id": lease_id, "job_kind": job_kind, "input_sha256": input_sha, "output_sha256": output_sha},
        "job_ext": {"transcript_sha256": "", "pow_hash_hex": "", "checkpoints_root_hex": ""},
        "device": {"device_pk_ed25519": device_pk_ed25519, "device_sig_over_submit_sha256": device_sig_over_submit_sha256},
        "audit": {"rate": audit_rate, "sample_idx0_included": bool(audit_sample_idx0_included), "chunk_size": int(audit_chunk_size)},
        "credits": {"awarded_i64": int(awarded_credits), "unit":"gmf_credit_v1"},
        "prev_entry_hash": prev_entry_hash,
    }

    receipt_sha256 = _sha256_hex(_canon_json(receipt))
    sig_hex = _sign(sk, receipt_sha256)

    rec = {"receipt": receipt, "receipt_sha256": receipt_sha256, "server_sig_ed25519_hex": sig_hex}
    with RECEIPTS_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")

    _write_daily_root(day_utc)
    return rec
