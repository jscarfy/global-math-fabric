import hashlib
from typing import List, Tuple, Dict, Any

def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def merkle_root_from_leaf_hashes(leaf_hashes: List[bytes]) -> bytes:
    if not leaf_hashes:
        return b"\x00" * 32
    level = leaf_hashes[:]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i+1] if (i+1) < len(level) else level[i]
            nxt.append(_h(a + b))
        level = nxt
    return level[0]

def build_merkle_proof(leaf_hashes: List[bytes], index0: int) -> Dict[str, Any]:
    """
    Returns proof for leaf at index0 (0-based):
      siblings: list of hex sibling hashes per level (bottom-up)
      directions: list of 'L'/'R' meaning sibling is left/right of current node at that level
    Verify:
      start = leaf_hash
      for each level: if sibling is left => h(sib||cur) else h(cur||sib)
    """
    n = len(leaf_hashes)
    if index0 < 0 or index0 >= n:
        raise ValueError("index out of range")

    siblings: List[str] = []
    directions: List[str] = []

    level = leaf_hashes[:]
    idx = index0

    while len(level) > 1:
        is_right = (idx % 2 == 1)
        if is_right:
            sib = level[idx - 1]
            siblings.append(sib.hex())
            directions.append("L")
        else:
            sib = level[idx + 1] if (idx + 1) < len(level) else level[idx]
            siblings.append(sib.hex())
            directions.append("R")

        # build next level
        nxt = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i+1] if (i+1) < len(level) else level[i]
            nxt.append(_h(a + b))
        level = nxt
        idx //= 2

    return {"siblings": siblings, "directions": directions, "index0": index0, "leaves": n}
