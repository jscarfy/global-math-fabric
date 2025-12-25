#!/usr/bin/env python3
import argparse, json, base64, hashlib, sys
from typing import Any, Dict, List

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def load_pub_pem(pem_bytes: bytes) -> Ed25519PublicKey:
    k = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(k, Ed25519PublicKey):
        raise ValueError("not ed25519 pubkey")
    return k

def verify_receipt_envelope(envelope: Dict[str, str], receipt_pub_pem: bytes) -> Dict[str, Any]:
    pk = load_pub_pem(receipt_pub_pem)
    msg = base64.b64decode(envelope["payload_b64"])
    sig = base64.b64decode(envelope["signature_b64"])
    pk.verify(sig, msg)
    payload = json.loads(msg.decode("utf-8"))
    # optional receipt_id self-check
    rid = payload.get("receipt_id")
    if rid:
        recomputed = hashlib.sha256(canon(payload).encode("utf-8")).hexdigest()
        if recomputed != rid:
            raise ValueError("receipt_id_mismatch")
    return payload

def verify_guardian_sigset(sigset: Dict[str, Any], guardian_set: Dict[str, Any], rules_sha256: str) -> None:
    # msg must bind rules_sha256
    msg = str(sigset.get("msg") or "")
    if rules_sha256 not in msg:
        raise ValueError("sigset_msg_not_binding_rules_sha256")
    thr = int(sigset.get("threshold") or guardian_set.get("threshold") or 1)
    signer_map = {str(s["id"]): str(s["pub_pem"]) for s in guardian_set.get("signers", [])}
    ok = 0
    msg_b = msg.encode("utf-8")
    for ent in sigset.get("signatures", []):
        sid = str(ent.get("signer") or "")
        sig_b64 = str(ent.get("sig_b64") or "")
        if sid not in signer_map or not sig_b64:
            continue
        pk = load_pub_pem(open(signer_map[sid], "rb").read())
        sig = base64.b64decode(sig_b64.encode("ascii"))
        try:
            pk.verify(sig, msg_b)
            ok += 1
        except Exception:
            continue
    if ok < thr:
        raise ValueError(f"guardian_sigset_threshold_not_met ok={ok} thr={thr}")

def merkle_verify(leaf_hex: str, siblings: List[str], directions: List[str]) -> str:
    cur = bytes.fromhex(leaf_hex)
    def h(b: bytes) -> bytes:
        return hashlib.sha256(b).digest()
    for sib_hex, d in zip(siblings, directions):
        sib = bytes.fromhex(sib_hex)
        if d == "L":
            cur = h(sib + cur)
        elif d == "R":
            cur = h(cur + sib)
        else:
            raise ValueError("bad direction")
    return cur.hex()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True, help="bundle json file (from /ledger/receipt/proof_bundle)")
    ap.add_argument("--receipt-pub", required=True, help="receipt signer public key PEM path (e.g. keys/receipt-dev.ed25519.pub.pem)")
    args = ap.parse_args()

    obj = json.load(open(args.bundle, "r", encoding="utf-8"))
    if not obj.get("ok"):
        raise SystemExit("bundle ok=false")

    b = obj["bundle"]
    env = b["envelope"]
    gov = b["governance"]
    inc = b["inclusion"]

    # 1) Verify rules hash
    rules_sha = sha256_hex(canon(gov["rules"]))
    if rules_sha != gov["rules_sha256"]:
        raise SystemExit("RULES_SHA256_MISMATCH")

    # 2) Verify guardian sigset threshold
    verify_guardian_sigset(gov["sigset"], gov["guardian_set"], gov["rules_sha256"])

    # 3) Verify receipt envelope signature
    receipt_payload = verify_receipt_envelope(env, open(args.receipt_pub, "rb").read())

    # 4) Verify payload binds rules hash
    if str(receipt_payload.get("rules_sha256")) != str(gov["rules_sha256"]):
        raise SystemExit("RECEIPT_RULES_SHA256_MISMATCH")

    # 5) Verify inclusion proof to anchor root
    leaf_sha = inc["leaf_sha256"]
    proof = inc["proof"]
    root_calc = merkle_verify(leaf_sha, proof["siblings"], proof["directions"])
    if root_calc != inc["ledger_root_sha256"]:
        raise SystemExit("MERKLE_PROOF_ROOT_MISMATCH")

    # 6) If checkpoint present, optionally sanity-check it binds same root/rules
    cp = inc.get("checkpoint")
    if cp:
        if str(cp.get("ledger_root_sha256")) != inc["ledger_root_sha256"]:
            raise SystemExit("CHECKPOINT_ROOT_MISMATCH")
        if str(cp.get("rules_sha256")) != gov["rules_sha256"]:
            raise SystemExit("CHECKPOINT_RULES_SHA_MISMATCH")

    print(json.dumps({
        "ok": True,
        "receipt_id": b["receipt_id"],
        "awarded_credits": receipt_payload.get("awarded_credits"),
        "ledger_root": inc["ledger_root_sha256"],
        "anchor": inc.get("anchor"),
    }, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
