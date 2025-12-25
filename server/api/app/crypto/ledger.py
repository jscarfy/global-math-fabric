from app.crypto.merkle_cache import MerkleCache
import os, json, hashlib
from typing import List, Tuple, Any

LEDGER_JSONL_DEFAULT = "ledger/receipts/receipts.jsonl"

def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def merkle_root_from_lines(lines: List[bytes]) -> str:
    if not lines:
        return ("00" * 32)
    level = [_h(x) for x in lines]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i+1] if (i+1) < len(level) else level[i]
            nxt.append(_h(a + b))
        level = nxt
    return level[0].hex()

def ledger_path() -> str:
    return os.environ.get("GMF_LEDGER_JSONL", LEDGER_JSONL_DEFAULT)

def ensure_ledger_file() -> None:
    p = ledger_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    if not os.path.exists(p):
        open(p, "a", encoding="utf-8").close()

def read_all_lines() -> List[bytes]:
    ensure_ledger_file()
    p = ledger_path()
    out = []
    with open(p, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                out.append(ln.encode("utf-8"))
    return out

def current_root_and_len() -> Tuple[str, int]:
    lines = read_all_lines()
    return merkle_root_from_lines(lines), len(lines)

def append_envelope_line(envelope_obj: Any) -> Tuple[int, str, str]:
    """
    Append one JSON line (envelope dict) to ledger.
    Returns: (seq_1based, root_before, root_after)
    """
    ensure_ledger_file()
    p = ledger_path()

    root_before, n = current_root_and_len()
    seq = n + 1

    line = json.dumps(envelope_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    # cache leaf hash for O(log n) roots/proofs later
    try:
        mc = merkle_cache()
        mc.ensure_leaf_hash(seq - 1, line.encode('utf-8'))
    except Exception:
        pass
    with open(p, "a", encoding="utf-8") as f:
        f.write(line + "\n")

    root_after, _ = current_root_and_len()
    return seq, root_before, root_after

def tail(limit: int = 20) -> List[str]:
    ensure_ledger_file()
    p = ledger_path()
    limit = max(1, min(200, int(limit)))
    with open(p, "r", encoding="utf-8") as f:
        lines = [ln.rstrip("\n") for ln in f if ln.strip()]
    return lines[-limit:]


def merkle_db_path() -> str:
    return os.environ.get("GMF_MERKLE_DB", "ledger/cache/merkle_nodes.sqlite")

def merkle_cache() -> MerkleCache:
    return MerkleCache(merkle_db_path())
