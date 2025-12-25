#!/usr/bin/env python3
import os, sqlite3, hashlib

LEDGER = os.environ.get("GMF_LEDGER_JSONL", "ledger/receipts/receipts.jsonl")
DB     = os.environ.get("GMF_MERKLE_DB", "ledger/cache/merkle_nodes.sqlite")

def h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

os.makedirs(os.path.dirname(DB), exist_ok=True)
conn = sqlite3.connect(DB)
conn.execute("PRAGMA journal_mode=WAL;")
conn.execute("""
  CREATE TABLE IF NOT EXISTS nodes(
    level INTEGER NOT NULL,
    idx   INTEGER NOT NULL,
    hash  BLOB NOT NULL,
    PRIMARY KEY(level, idx)
  );
""")

# wipe leaves only (keep internal nodes; they can be recomputed if needed)
conn.execute("DELETE FROM nodes WHERE level=0;")
conn.commit()

if not os.path.exists(LEDGER):
    open(LEDGER, "a").close()

with open(LEDGER, "rb") as f:
    i = 0
    for line in f:
        line = line.strip()
        if not line:
            continue
        conn.execute("INSERT OR REPLACE INTO nodes(level, idx, hash) VALUES(0, ?, ?)", (i, h(line)))
        i += 1

conn.commit()
print(f"rebuilt leaves: {i} into {DB}")
