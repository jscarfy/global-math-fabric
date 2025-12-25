import json, hashlib
from typing import List, Dict, Any, Tuple

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def canon_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8")

def leaf_hash_from_receipt(receipt: Dict[str, Any]) -> bytes:
    return sha256(canon_json(receipt))

def build_levels(leaves: List[bytes]) -> List[List[bytes]]:
    """
    Bitcoin-style duplicate-last on odd levels.
    levels[0] = leaves, levels[-1] = [root]
    """
    if not leaves:
        z = sha256(b"")
        return [[z]]
    levels = [leaves[:]]
    while len(levels[-1]) > 1:
        cur = levels[-1][:]
        if len(cur) % 2 == 1:
            cur.append(cur[-1])
        nxt=[]
        for i in range(0, len(cur), 2):
            nxt.append(sha256(cur[i] + cur[i+1]))
        levels.append(nxt)
    return levels

def merkle_root(leaves: List[bytes]) -> bytes:
    return build_levels(leaves)[-1][0]

def merkle_proof(levels: List[List[bytes]], index: int) -> List[Dict[str, Any]]:
    proof=[]
    idx=index
    for lvl in range(len(levels)-1):
        cur = levels[lvl][:]
        if len(cur) % 2 == 1:
            cur.append(cur[-1])
        sib = idx ^ 1
        proof.append({
            "level": lvl,
            "index": idx,
            "sibling_index": sib,
            "sibling_hash": cur[sib].hex(),
            "direction": "left" if sib < idx else "right",
        })
        idx //= 2
    return proof

def leaves_sha256(leaves: List[bytes]) -> str:
    h=hashlib.sha256()
    for x in leaves:
        h.update(x)
    return h.hexdigest()
