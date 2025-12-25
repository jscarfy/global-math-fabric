import os, json
from fastapi import APIRouter
from fastapi.responses import JSONResponse, Response
from typing import Optional, Dict, Any

from .merkle_lib import leaf_hash_from_receipt, build_levels, merkle_proof, merkle_root, leaves_sha256

MERKLE_DIR = os.environ.get("GMF_MERKLE_DIR", "ledger/merkle_roots")
RECEIPTS_DIR = os.environ.get("GMF_RECEIPTS_DIR", "ledger/receipts")

router = APIRouter(prefix="/api/merkle", tags=["merkle"])

def _root_path(account_id: str, day: str) -> str:
    return os.path.join(MERKLE_DIR, account_id, f"{day}.json")

def _receipts_path(account_id: str, day: str) -> str:
    return os.path.join(RECEIPTS_DIR, account_id, f"{day}.jsonl")

@router.get("/root/{account_id}/{day}")
def get_root(account_id: str, day: str):
    fp = _root_path(account_id, day)
    if not os.path.exists(fp):
        return JSONResponse(status_code=404, content={"ok": False, "reason": "root_not_found"})
    # return raw json
    return Response(content=open(fp, "rb").read(), media_type="application/json")

@router.get("/proof/{account_id}/{day}/{receipt_index}")
def get_proof(account_id: str, day: str, receipt_index: int):
    fp = _receipts_path(account_id, day)
    if not os.path.exists(fp):
        return JSONResponse(status_code=404, content={"ok": False, "reason": "partitioned_receipts_not_found"})

    if receipt_index < 0:
        return JSONResponse(status_code=400, content={"ok": False, "reason": "bad_receipt_index"})

    leaves=[]
    chosen: Optional[Dict[str, Any]] = None

    with open(fp, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line=line.strip()
            if not line:
                continue
            r=json.loads(line)
            lh = leaf_hash_from_receipt(r)
            if len(leaves) == receipt_index:
                chosen = r
            leaves.append(lh)

    if chosen is None:
        return JSONResponse(status_code=404, content={"ok": False, "reason": "receipt_index_out_of_range"})

    levels = build_levels(leaves)
    root = levels[-1][0].hex()
    proof = merkle_proof(levels, receipt_index)

    out = {
        "ok": True,
        "account_id": account_id,
        "day": day,
        "receipt_index": receipt_index,
        "count": len(leaves),
        "leaf_hash": leaves[receipt_index].hex(),
        "root": root,
        "leaves_sha256": leaves_sha256(leaves),
        "proof": proof,
        "receipt": chosen,
        "verify_rule": "leaf=sha256(canonical_json(receipt)); merkle=sha256(left||right); odd duplicate-last each level",
    }
    return out

@router.get("/verify_rule")
def verify_rule():
    return {
        "ok": True,
        "leaf_rule": "sha256(canonical_json(receipt)) where canonical_json=sorted_keys,separators=(',',':'),utf8",
        "tree_rule": "bitcoin-style duplicate-last if odd; parent=sha256(left||right)",
    }
