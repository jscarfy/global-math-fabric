from app.crypto.merkle_cache import MerkleCache
import os, json, base64
from datetime import datetime, timezone
from typing import Any, Dict, Tuple, List

from app.crypto.governance import load_json, load_ed25519_pub_pem
from app.crypto.ledger import ledger_path, read_all_lines
from app.crypto import ledger as ledger_mod
from app.crypto.merkle import _h, merkle_root_from_leaf_hashes

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def checkpoints_dir() -> str:
    return os.environ.get("GMF_LEDGER_CHECKPOINTS_DIR", "ledger/checkpoints")

def pending_dir() -> str:
    return os.environ.get("GMF_LEDGER_PENDING_DIR", "ledger/pending_checkpoints")

def ensure_dirs():
    os.makedirs(checkpoints_dir(), exist_ok=True)
    os.makedirs(pending_dir(), exist_ok=True)

def leaf_hashes_from_ledger_lines(lines: List[bytes]) -> List[bytes]:
    # leaf hash = sha256(line_bytes)
    return [_h(x) for x in lines]

def current_ledger_root_and_len() -> Tuple[str, int]:
    # Fast path: use MerkleCache meta ledger_entries (maintained on append)
    n = 0
    try:
        n = int(ledger_mod.ledger_entries_meta())
    except Exception:
        n = 0

    if n <= 0:
        return ("00"*32), 0

    mc = _mc()
    # Leaves should already exist because append stores them; but be defensive:
    # if cache missing leaves (fresh DB), rebuild leaves once.
    missing = False
    for i in range(0, min(n, 32)):  # quick spot-check first 32
        if mc.get(0, i) is None:
            missing = True
            break
    if missing:
        lines = read_all_lines()
        for i, b in enumerate(lines):
            if mc.get(0, i) is None:
                mc.ensure_leaf_hash(i, b)
        mc.meta_set_int("ledger_entries", len(lines))
        n = len(lines)

    return mc.root_for_n(n), n

    # ensure leaves exist (best-effort); internal nodes are lazy
    mc = _mc()
    for i, b in enumerate(lines):
        if mc.get(0, i) is None:
            mc.ensure_leaf_hash(i, b)
    return mc.root_for_n(n), n

def guardian_set() -> Dict[str, Any]:
    gset_path = os.environ.get("GMF_GUARDIAN_SET_PATH", "governance/signers/guardian_set_v1.json")
    return load_json(gset_path)

def verify_threshold_signatures_ed25519(msg: str, signatures: List[Dict[str, Any]], threshold: int, gset: Dict[str, Any]) -> Tuple[bool, int]:
    signer_map = {str(s["id"]): str(s["pub_pem"]) for s in gset.get("signers", [])}
    ok = 0
    msg_b = msg.encode("utf-8")

    for ent in signatures:
        sid = str(ent.get("signer") or "")
        sig_b64 = str(ent.get("sig_b64") or "")
        if sid not in signer_map or not sig_b64:
            continue
        try:
            pk = load_ed25519_pub_pem(signer_map[sid])
            sig = base64.b64decode(sig_b64.encode("ascii"))
            pk.verify(sig, msg_b)
            ok += 1
        except Exception:
            continue

    return (ok >= threshold), ok

def create_pending_checkpoint(rules_sha256: str) -> Dict[str, Any]:
    """
    Server-generated request: no signatures.
    Guardians sign msg offline.
    """
    ensure_dirs()
    root, n = current_ledger_root_and_len()
    ts = now_iso()
    msg = f"GMF_LEDGER_CHECKPOINT|{root}|{rules_sha256}|{n}|{ts}"

    req = {
        "checkpoint_v": 1,
        "ts": ts,
        "ledger_root_sha256": root,
        "entries": n,
        "rules_sha256": rules_sha256,
        "guardian_set_id": guardian_set().get("guardian_set_id", "guardian_set_v1"),
        "msg": msg,
        "sig_suite": "ed25519",
        "threshold": int(guardian_set().get("threshold", 1)),
        "signatures": []
    }

    # store as pending file for auditability
    fn = os.path.join(pending_dir(), f"pending-{ts}.json")
    with open(fn, "w", encoding="utf-8") as f:
        json.dump(req, f, ensure_ascii=False, sort_keys=True, indent=2)

    return req

def accept_checkpoint(checkpoint: Dict[str, Any], rules_sha256_expected: str) -> Dict[str, Any]:
    ensure_dirs()
    gset = guardian_set()
    thr = int(checkpoint.get("threshold") or gset.get("threshold") or 1)

    # basic checks
    if checkpoint.get("sig_suite") != "ed25519":
        raise ValueError("unsupported sig_suite")
    if str(checkpoint.get("rules_sha256")) != str(rules_sha256_expected):
        raise ValueError("rules_sha256 mismatch")
    if str(checkpoint.get("guardian_set_id")) != str(gset.get("guardian_set_id", "guardian_set_v1")):
        raise ValueError("guardian_set_id mismatch")

    # msg must match fields
    root = str(checkpoint.get("ledger_root_sha256"))
    n = int(checkpoint.get("entries") or 0)
    ts = str(checkpoint.get("ts"))
    msg = str(checkpoint.get("msg"))
    must = f"GMF_LEDGER_CHECKPOINT|{root}|{rules_sha256_expected}|{n}|{ts}"
    if msg != must:
        raise ValueError("msg does not bind fields")

    # verify signatures
    ok, cnt = verify_threshold_signatures_ed25519(msg, checkpoint.get("signatures") or [], thr, gset)
    if not ok:
        raise ValueError(f"threshold not met: ok={cnt} thr={thr}")

    # sanity: checkpoint root should correspond to some prefix of current ledger (>=n entries)
    # We recompute root for first n lines from current ledger and compare.
    lines = read_all_lines()
    if n > len(lines):
        raise ValueError("checkpoint entries exceed current ledger length")
    mc = _mc()
    for i, b in enumerate(lines[:n]):
        if mc.get(0, i) is None:
            mc.ensure_leaf_hash(i, b)
    recomputed = mc.root_for_n(n)
    if recomputed != root:
        raise ValueError("checkpoint root not matching current ledger prefix")

    # store accepted checkpoint
    out = os.path.join(checkpoints_dir(), f"checkpoint-{ts}.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(checkpoint, f, ensure_ascii=False, sort_keys=True, indent=2)

    return {"stored": out, "verified_signatures": cnt, "threshold": thr}

def latest_checkpoint() -> Dict[str, Any] | None:
    ensure_dirs()
    cps = []
    for fn in os.listdir(checkpoints_dir()):
        if fn.startswith("checkpoint-") and fn.endswith(".json"):
            cps.append(fn)
    if not cps:
        return None
    cps.sort()
    path = os.path.join(checkpoints_dir(), cps[-1])
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _mc() -> MerkleCache:
    dbp = os.environ.get("GMF_MERKLE_DB", "ledger/cache/merkle_nodes.sqlite")
    return MerkleCache(dbp)
