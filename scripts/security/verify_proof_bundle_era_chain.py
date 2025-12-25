#!/usr/bin/env python3
import argparse, json, base64, hashlib, os, glob
from typing import Any, Dict, List, Tuple, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha256_hex_utf8(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def load_pub_pem(path: str) -> Ed25519PublicKey:
    pem = open(path, "rb").read()
    k = serialization.load_pem_public_key(pem)
    if not isinstance(k, Ed25519PublicKey):
        raise ValueError("not ed25519 pubkey")
    return k

def load_json(path: str) -> Any:
    return json.load(open(path, "r", encoding="utf-8"))

def verify_threshold_ed25519(msg: str, signatures: List[Dict[str,str]], guardian_set: Dict[str,Any]) -> Tuple[bool,int,int]:
    thr = int(guardian_set.get("threshold", 1))
    signer_map = {str(s["id"]): str(s["pub_pem"]) for s in guardian_set.get("signers", [])}
    ok = 0
    msg_b = msg.encode("utf-8")
    for ent in signatures:
        sid = str(ent.get("signer") or "")
        sig_b64 = str(ent.get("sig_b64") or "")
        if sid not in signer_map or not sig_b64:
            continue
        try:
            pk = load_pub_pem(signer_map[sid])
            pk.verify(base64.b64decode(sig_b64.encode("ascii")), msg_b)
            ok += 1
        except Exception:
            pass
    return (ok >= thr), ok, thr

def merkle_verify(leaf_hex: str, siblings: List[str], directions: List[str]) -> str:
    cur = bytes.fromhex(leaf_hex)
    for sib_hex, d in zip(siblings, directions):
        sib = bytes.fromhex(sib_hex)
        if d == "L":
            cur = h(sib + cur)
        elif d == "R":
            cur = h(cur + sib)
        else:
            raise ValueError("bad direction")
    return cur.hex()

def load_registry(reg_path: str) -> Dict[str,Any]:
    reg = load_json(reg_path)
    sets = reg.get("sets", {}) or {}
    return {"active_guardian_set_id": reg.get("active_guardian_set_id"), "sets": sets}

def load_guardian_set_by_id(reg: Dict[str,Any], set_id: str) -> Dict[str,Any]:
    path = reg["sets"].get(set_id)
    if not path:
        raise ValueError(f"unknown guardian_set_id: {set_id}")
    return load_json(path)

def compute_guardian_set_sha256(gset_obj: Dict[str,Any]) -> str:
    return sha256_hex_utf8(canon(gset_obj))

def build_trust_closure(reg: Dict[str,Any], transitions_dir: str, trusted_roots: List[str]) -> Tuple[Dict[str,bool], List[Dict[str,Any]]]:
    """
    trusted_roots: initial trusted guardian_set_ids (e.g. v1 known from physical archives)
    transitions: files signed by old set that certify new set json hash.
    """
    trusted = {sid: True for sid in trusted_roots}
    accepted_transitions: List[Dict[str,Any]] = []

    files = sorted(glob.glob(os.path.join(transitions_dir, "*.json")))
    changed = True
    while changed:
        changed = False
        for fp in files:
            t = load_json(fp)
            if t.get("kind") != "guardian_set_transition":
                continue
            old_id = str(t.get("old_guardian_set_id"))
            new_id = str(t.get("new_guardian_set_id"))
            if not trusted.get(old_id, False):
                continue
            if trusted.get(new_id, False):
                continue

            # verify new set sha
            gset_new = load_guardian_set_by_id(reg, new_id)
            new_sha = compute_guardian_set_sha256(gset_new)
            if new_sha != str(t.get("new_guardian_set_sha256")):
                continue

            # verify signatures with OLD set
            gset_old = load_guardian_set_by_id(reg, old_id)
            ok, cnt, thr = verify_threshold_ed25519(str(t.get("msg")), list(t.get("signatures") or []), gset_old)
            if not ok:
                continue

            trusted[new_id] = True
            accepted_transitions.append({"file": fp, "old": old_id, "new": new_id, "verified": cnt, "threshold": thr})
            changed = True

    return trusted, accepted_transitions

def load_attestations(att_dir: str) -> List[Dict[str,Any]]:
    out = []
    for fp in sorted(glob.glob(os.path.join(att_dir, "*.json"))):
        try:
            a = load_json(fp)
            a["_file"] = fp
            out.append(a)
        except Exception:
            pass
    return out

def find_attestations_for_old_msg_sha(attestations: List[Dict[str,Any]], old_msg_sha: str) -> List[Dict[str,Any]]:
    res = []
    for a in attestations:
        if str(a.get("kind")) != "msg_hash_re_attestation":
            continue
        if str(a.get("old_msg_sha256")) == old_msg_sha:
            res.append(a)
    return res

def verify_receipt_envelope(envelope: Dict[str,str], receipt_pub_pem_path: str) -> Dict[str,Any]:
    pk = load_pub_pem(receipt_pub_pem_path)
    msg = base64.b64decode(envelope["payload_b64"].encode("ascii"))
    sig = base64.b64decode(envelope["signature_b64"].encode("ascii"))
    pk.verify(sig, msg)
    payload = json.loads(msg.decode("utf-8"))
    return payload

def verify_rules(sigset: Dict[str,Any], rules: Dict[str,Any], reg: Dict[str,Any], trusted: Dict[str,bool], attestations: List[Dict[str,Any]]) -> Dict[str,Any]:
    rules_sha = sha256_hex_utf8(canon(rules))
    if rules_sha != str(sigset.get("rules_sha256")):
        return {"ok": False, "error": "rules_sha_mismatch"}

    set_id = str(sigset.get("guardian_set_id") or "")
    msg = str(sigset.get("msg") or "")
    # direct verify only if set trusted
    if set_id and trusted.get(set_id, False):
        gset = load_guardian_set_by_id(reg, set_id)
        ok, cnt, thr = verify_threshold_ed25519(msg, list(sigset.get("signatures") or []), gset)
        if ok:
            return {"ok": True, "mode": "direct", "guardian_set_id": set_id, "verified": cnt, "threshold": thr, "rules_sha256": rules_sha}

    # fallback: attestations by some trusted set endorse msg hash
    old_msg_sha = sha256_hex_utf8(msg)
    candidates = find_attestations_for_old_msg_sha(attestations, old_msg_sha)
    for a in candidates:
        new_set = str(a.get("new_guardian_set_id") or "")
        if not trusted.get(new_set, False):
            continue
        gset_new = load_guardian_set_by_id(reg, new_set)
        ok, cnt, thr = verify_threshold_ed25519(str(a.get("msg")), list(a.get("signatures") or []), gset_new)
        if ok:
            return {"ok": True, "mode": "attested", "attestation_file": a.get("_file"), "endorsed_by": new_set,
                    "verified": cnt, "threshold": thr, "rules_sha256": rules_sha, "old_msg_sha256": old_msg_sha}

    return {"ok": False, "error": "rules_sigset_untrusted_or_invalid", "guardian_set_id": set_id, "old_msg_sha256": sha256_hex_utf8(msg)}

def verify_checkpoint(cp: Dict[str,Any], reg: Dict[str,Any], trusted: Dict[str,bool], attestations: List[Dict[str,Any]]) -> Dict[str,Any]:
    set_id = str(cp.get("guardian_set_id") or "")
    msg = str(cp.get("msg") or "")
    if set_id and trusted.get(set_id, False):
        gset = load_guardian_set_by_id(reg, set_id)
        ok, cnt, thr = verify_threshold_ed25519(msg, list(cp.get("signatures") or []), gset)
        if ok:
            return {"ok": True, "mode": "direct", "guardian_set_id": set_id, "verified": cnt, "threshold": thr,
                    "ledger_root_sha256": cp.get("ledger_root_sha256"), "entries": cp.get("entries")}

    old_msg_sha = sha256_hex_utf8(msg)
    candidates = find_attestations_for_old_msg_sha(attestations, old_msg_sha)
    for a in candidates:
        new_set = str(a.get("new_guardian_set_id") or "")
        if not trusted.get(new_set, False):
            continue
        gset_new = load_guardian_set_by_id(reg, new_set)
        ok, cnt, thr = verify_threshold_ed25519(str(a.get("msg")), list(a.get("signatures") or []), gset_new)
        if ok:
            return {"ok": True, "mode": "attested", "attestation_file": a.get("_file"), "endorsed_by": new_set,
                    "verified": cnt, "threshold": thr, "ledger_root_sha256": cp.get("ledger_root_sha256"),
                    "entries": cp.get("entries"), "old_msg_sha256": old_msg_sha}

    return {"ok": False, "error": "checkpoint_untrusted_or_invalid", "guardian_set_id": set_id, "old_msg_sha256": old_msg_sha}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True, help="bundle json file (from /ledger/receipt/proof_bundle)")
    ap.add_argument("--receipt-pub", required=True, help="receipt signer public key PEM path")
    ap.add_argument("--registry", default="governance/signers/registry.json", help="guardian registry json path")
    ap.add_argument("--transitions-dir", default="governance/signers/transitions", help="transitions directory")
    ap.add_argument("--attestations-dir", default="ledger/attestations", help="attestations directory")
    ap.add_argument("--trust-root", action="append", default=[], help="trusted root guardian_set_id (repeatable). default=registry.active_guardian_set_id")
    args = ap.parse_args()

    obj = load_json(args.bundle)
    if not obj.get("ok"):
        raise SystemExit("bundle ok=false")

    b = obj["bundle"]
    gov = b["governance"]
    inc = b["inclusion"]

    reg = load_registry(args.registry)
    trust_roots = args.trust_root[:] if args.trust_root else [str(reg.get("active_guardian_set_id") or "guardian_set_v1")]
    trusted, accepted_transitions = build_trust_closure(reg, args.transitions_dir, trust_roots)

    attestations = load_attestations(args.attestations_dir)

    # 1) verify receipt envelope signature
    payload = verify_receipt_envelope(b["envelope"], args.receipt_pub)

    # 2) verify rules (direct or attested)
    rules_res = verify_rules(gov["sigset"], gov["rules"], reg, trusted, attestations)

    # 3) verify merkle inclusion proof
    proof = inc["proof"]
    root_calc = merkle_verify(inc["leaf_sha256"], proof["siblings"], proof["directions"])
    if root_calc != inc["ledger_root_sha256"]:
        raise SystemExit("MERKLE_PROOF_ROOT_MISMATCH")

    # 4) verify checkpoint (if provided)
    cp_res = None
    cp = inc.get("checkpoint")
    if cp:
        cp_res = verify_checkpoint(cp, reg, trusted, attestations)
        # basic consistency checks (if checkpoint is the anchor)
        if str(cp.get("ledger_root_sha256")) != str(inc["ledger_root_sha256"]):
            raise SystemExit("CHECKPOINT_ROOT_MISMATCH")

    # 5) payload binds rules hash
    if str(payload.get("rules_sha256")) != str(gov.get("rules_sha256")):
        raise SystemExit("RECEIPT_RULES_SHA256_MISMATCH")

    out = {
        "ok": True,
        "receipt_id": b.get("receipt_id"),
        "awarded_credits": payload.get("awarded_credits"),
        "rules_verification": rules_res,
        "checkpoint_verification": cp_res,
        "merkle_anchor_root": inc["ledger_root_sha256"],
        "trusted_roots": trust_roots,
        "trusted_sets_count": sum(1 for k,v in trusted.items() if v),
        "accepted_transitions": accepted_transitions[:20],
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
