#!/usr/bin/env python3
import os
from app.crypto.merkle_cache import MerkleCache, root_level
from app.crypto import ledger as ledger_mod

def main():
    dbp = os.environ.get("GMF_MERKLE_DB", "ledger/cache/merkle_nodes.sqlite")
    mc = MerkleCache(dbp)
    n = ledger_mod.ledger_entries_meta()

    budget = int(os.environ.get("GMF_PREWARM_BUDGET", "200000"))
    upto = root_level(n) if n > 0 else 0

    res = mc.prewarm(n, upto_level=upto, budget_nodes=budget)
    print({"n": n, "upto": upto, "budget": budget, "res": res, "cached_nodes": mc.count_nodes(),
           "prewarm_n": mc.meta_get_int("prewarm_n_leaves"), "prewarm_upto": mc.meta_get_int("prewarm_upto_level")})

if __name__ == "__main__":
    main()
