import os, sqlite3, hashlib, json, math
from typing import Optional, Tuple, List, Dict, Any

def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def canon_json_line(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b

def nodes_count(n_leaves: int, level: int) -> int:
    # level=0: leaves count = n
    # each level halves with ceil
    return ceil_div(n_leaves, 1 << level)

def root_level(n_leaves: int) -> int:
    if n_leaves <= 1:
        return 0
    lvl = 0
    c = n_leaves
    while c > 1:
        c = ceil_div(c, 2)
        lvl += 1
    return lvl

class MerkleCache:
    """
    Cache node hashes for the pad-last Merkle tree defined by:
      - leaves are sha256(line_bytes)
      - parent = sha256(left||right)
      - if right is missing at a level, use right=left (duplicate last)
    Node indices at each level are 0..count(level)-1 where count(level)=ceil(n/2^level).
    """
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("""
          CREATE TABLE IF NOT EXISTS nodes(
            level INTEGER NOT NULL,
            idx   INTEGER NOT NULL,
            hash  BLOB NOT NULL,
            PRIMARY KEY(level, idx)
          );
        """)
        self._conn.execute("""
          CREATE TABLE IF NOT EXISTS meta(
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL
          );
        """)

    def get(self, level: int, idx: int) -> Optional[bytes]:
        row = self._conn.execute("SELECT hash FROM nodes WHERE level=? AND idx=?", (level, idx)).fetchone()
        return row[0] if row else None

    def put(self, level: int, idx: int, hsh: bytes) -> None:
        self._conn.execute("INSERT OR REPLACE INTO nodes(level, idx, hash) VALUES(?,?,?)", (level, idx, hsh))

    def meta_get(self, k: str) -> Optional[str]:
        row = self._conn.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return row[0] if row else None

    def meta_set(self, k: str, v: str) -> None:
        self._conn.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (k, v))

    def ensure_leaf_hash(self, leaf_idx: int, line_bytes: bytes) -> bytes:
        existing = self.get(0, leaf_idx)
        if existing is not None:
            return existing
        lh = _h(line_bytes)
        self.put(0, leaf_idx, lh)
        return lh

    def node_hash(self, level: int, idx: int, n_leaves: int) -> bytes:
        """
        Returns hash for node(level, idx) for a tree with n_leaves.
        Lazy-memoized in SQLite.
        """
        if n_leaves <= 0:
            return b"\x00" * 32

        cnt = nodes_count(n_leaves, level)
        if idx < 0 or idx >= cnt:
            raise ValueError("node idx out of range")

        cached = self.get(level, idx)
        if cached is not None:
            return cached

        if level == 0:
            # leaf must already exist (we can’t reconstruct line bytes here)
            raise ValueError("leaf missing in cache; rebuild leaves first")

        left = self.node_hash(level - 1, idx * 2, n_leaves)
        right_idx = idx * 2 + 1
        prev_cnt = nodes_count(n_leaves, level - 1)
        if right_idx >= prev_cnt:
            right = left  # pad-last duplicate
        else:
            right = self.node_hash(level - 1, right_idx, n_leaves)

        ph = _h(left + right)
        self.put(level, idx, ph)
        return ph

    def root_for_n(self, n_leaves: int) -> str:
        if n_leaves <= 0:
            return ("00" * 32)
        lvl = root_level(n_leaves)
        r = self.node_hash(lvl, 0, n_leaves)
        return r.hex()

    def proof_for_seq(self, seq_1based: int, n_anchor: int) -> Dict[str, Any]:
        """
        Inclusion proof for leaf at seq (1-based) within first n_anchor leaves.
        Returns siblings+directions exactly like earlier endpoint expects.
        """
        idx = seq_1based - 1
        if idx < 0 or idx >= n_anchor:
            raise ValueError("seq out of anchor range")

        siblings: List[str] = []
        directions: List[str] = []

        level = 0
        cur_idx = idx
        cnt = nodes_count(n_anchor, level)

        # leaf hash must exist
        leaf = self.get(0, cur_idx)
        if leaf is None:
            raise ValueError("leaf missing in cache; rebuild leaves first")

        while cnt > 1:
            sib_idx = cur_idx ^ 1
            if sib_idx >= cnt:
                sib = self.node_hash(level, cur_idx, n_anchor)  # self-dup
                # direction doesn't matter if equal; keep "R"
                siblings.append(sib.hex())
                directions.append("R")
            else:
                sib = self.node_hash(level, sib_idx, n_anchor)
                # if cur is right child, sibling is left
                if (cur_idx % 2) == 1:
                    siblings.append(sib.hex())
                    directions.append("L")
                else:
                    siblings.append(sib.hex())
                    directions.append("R")

            # move up
            cur_idx //= 2
            level += 1
            cnt = nodes_count(n_anchor, level)

        return {"siblings": siblings, "directions": directions, "index0": idx, "leaves": n_anchor}


    def meta_get_int(self, k: str) -> Optional[int]:
        v = self.meta_get(k)
        if v is None:
            return None
        try:
            return int(v)
        except Exception:
            return None

    def meta_set_int(self, k: str, v: int) -> None:
        self.meta_set(k, str(int(v)))


    def count_nodes(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM nodes").fetchone()
        return int(row[0] or 0)

    def prewarm(self, n_leaves: int, upto_level: Optional[int] = None, budget_nodes: int = 200000) -> dict:
        """
        Compute and cache missing internal nodes up to upto_level (default: root level for n_leaves).
        Budget is number of (level,idx) computations attempted this call.
        Stores watermark in meta when a full prewarm completes.
        """
        if n_leaves <= 0:
            return {"ok": True, "n_leaves": 0, "computed": 0, "upto_level": 0}

        if upto_level is None:
            upto_level = root_level(n_leaves)

        budget_nodes = max(1, int(budget_nodes))
        computed = 0
        attempted = 0

        # prewarm internal levels only (level>=1)
        for lvl in range(1, int(upto_level) + 1):
            cnt = nodes_count(n_leaves, lvl)
            for idx in range(0, cnt):
                if attempted >= budget_nodes:
                    return {"ok": True, "partial": True, "n_leaves": n_leaves, "upto_level": upto_level, "computed": computed, "attempted": attempted}
                attempted += 1
                if self.get(lvl, idx) is not None:
                    continue
                _ = self.node_hash(lvl, idx, n_leaves)
                computed += 1

        # completed up to upto_level
        self.meta_set_int("prewarm_n_leaves", int(n_leaves))
        self.meta_set_int("prewarm_upto_level", int(upto_level))
        self.meta_set_int("prewarm_complete", 1)
        return {"ok": True, "partial": False, "n_leaves": n_leaves, "upto_level": upto_level, "computed": computed, "attempted": attempted}
