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

def load_json(path: str) -> Any:
    return json.load(open(path, "r", encoding="utf-8"))

def load_pub_pem(path: str) -> Ed25519PublicKey:
    pem = open(path, "rb").read()
    k = serialization.load_pem_public_key(pem)
    if not isinstance(k, Ed25519PublicKey):
        raise ValueError("not ed25519 pubkey")
    return k

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
    return {"active_guardian_set_id": reg.get("active_guardian_set_id"), "sets": reg.get("sets", {}) or {}}

def load_guardian_set_by_id(reg: Dict[str,Any], set_id: str) -> Dict[str,Any]:
    path = reg["sets"].get(set_id)
    if not path:
        raise ValueError(f"unknown guardian_set_id: {set_id}")
    return load_json(path)

def compute_guardian_set_sha256(gset_obj: Dict[str,Any]) -> str:
    return sha256_hex_utf8(canon(gset_obj))

def build_trust_closure(reg: Dict[str,Any], transitions_dir: str, trusted_roots: List[str]) -> Tuple[Dict[str,bool], List[Dict[str,Any]]]:
    trusted = {sid: True for sid in trusted_roots}
    accepted: List[Dict[str,Any]] = []
    files = sorted(glob.glob(os.path.join(transitions_dir, "*.json")))
    changed = True
    while changed:
        changed = False
        for fp in files:
            t = load_json(fp)
            if t.get("kind") != "guardian_set_transition":
                continue
            old_id = str(t.get("old_guardian_set_id") or "")
            new_id = str(t.get("new_guardian_set_id") or "")
            if not trusted.get(old_id, False) or trusted.get(new_id, False):
                continue
            gset_new = load_guardian_set_by_id(reg, new_id)
            if compute_guardian_set_sha256(gset_new) != str(t.get("new_guardian_set_sha256") or ""):
                continue
            gset_old = load_guardian_set_by_id(reg, old_id)
            ok, cnt, thr = verify_threshold_ed25519(str(t.get("msg") or ""), list(t.get("signatures") or []), gset_old)
            if not ok:
                continue
            trusted[new_id] = True
            accepted.append({"file": fp, "old": old_id, "new": new_id, "verified": cnt, "threshold": thr})
            changed = True
    return trusted, accepted

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

def find_reattest(attestations: List[Dict[str,Any]], old_msg_sha: str) -> List[Dict[str,Any]]:
    res = []
    for a in attestations:
        if str(a.get("kind")) != "msg_hash_re_attestation":
            continue
        if str(a.get("old_msg_sha256")) == old_msg_sha:
            res.append(a)
    return res

def verify_msg_direct_or_attested(msg: str, guardian_set_id: str, signatures: List[Dict[str,str]],
                                 reg: Dict[str,Any], trusted: Dict[str,bool], attestations: List[Dict[str,Any]]) -> Dict[str,Any]:
    """
    Verify a threshold signature message either:
      - direct using guardian_set_id (if trusted), OR
      - via re-attestation: some trusted newer set attests old msg sha
    """
    if guardian_set_id and trusted.get(guardian_set_id, False):
        gset = load_guardian_set_by_id(reg, guardian_set_id)
        ok, cnt, thr = verify_threshold_ed25519(msg, signatures, gset)
        if ok:
            return {"ok": True, "mode": "direct", "guardian_set_id": guardian_set_id, "verified": cnt, "threshold": thr}

    old_msg_sha = sha256_hex_utf8(msg)
    for a in find_reattest(attestations, old_msg_sha):
        new_set = str(a.get("new_guardian_set_id") or "")
        if not trusted.get(new_set, False):
            continue
        gset_new = load_guardian_set_by_id(reg, new_set)
        ok, cnt, thr = verify_threshold_ed25519(str(a.get("msg") or ""), list(a.get("signatures") or []), gset_new)
        if ok:
            return {"ok": True, "mode": "attested", "attestation_file": a.get("_file"), "endorsed_by": new_set, "old_msg_sha256": old_msg_sha,
                    "verified": cnt, "threshold": thr}

    return {"ok": False, "error": "untrusted_or_invalid", "guardian_set_id": guardian_set_id, "old_msg_sha256": sha256_hex_utf8(msg)}

def verify_receipt_envelope(envelope: Dict[str,str], receipt_pub_pem_path: str) -> Dict[str,Any]:
    pk = load_pub_pem(receipt_pub_pem_path)
    msg = base64.b64decode(envelope["payload_b64"].encode("ascii"))
    sig = base64.b64decode(envelope["signature_b64"].encode("ascii"))
    pk.verify(sig, msg)
    return json.loads(msg.decode("utf-8"))

def compute_rules_sha_from_file(path: str) -> str:
    return sha256_hex_utf8(canon(load_json(path)))

def verify_rules_entry(entry: Dict[str,Any], reg: Dict[str,Any], trusted: Dict[str,bool], attestations: List[Dict[str,Any]]) -> Dict[str,Any]:
    rules_path = str(entry.get("rules_path") or "")
    sigset_path = str(entry.get("sigset_path") or "")
    if not rules_path or not sigset_path:
        return {"ok": False, "error": "missing_paths"}

    sigset = load_json(sigset_path)
    rules_sha = compute_rules_sha_from_file(rules_path)
    if rules_sha != str(sigset.get("rules_sha256") or ""):
        return {"ok": False, "error": "rules_sha_mismatch", "rules_path": rules_path, "sigset_path": sigset_path}

    gset_id = str(sigset.get("guardian_set_id") or "")
    msg = str(sigset.get("msg") or "")
    sigs = list(sigset.get("signatures") or [])
    ver = verify_msg_direct_or_attested(msg, gset_id, sigs, reg, trusted, attestations)
    if not ver.get("ok"):
        return {"ok": False, "error": "sigset_unverified", "rules_version": entry.get("rules_version"), "detail": ver}

    return {"ok": True, "rules_version": entry.get("rules_version"), "rules_sha256": rules_sha, "verification": ver,
            "effective_from_checkpoint_entries": int(entry.get("effective_from_checkpoint_entries") or 0)}

def load_rules_registry(path: str) -> Dict[str,Any]:
    return load_json(path)

def select_active_rules_sha(registry: Dict[str,Any], checkpoint_entries: int) -> Tuple[str,str]:
    rules = list(registry.get("rules") or [])
    if not rules:
        return ("", "")
    rules.sort(key=lambda x: int(x.get("effective_from_checkpoint_entries") or 0))
    chosen = rules[0]
    for r in rules:
        if int(r.get("effective_from_checkpoint_entries") or 0) <= checkpoint_entries:
            chosen = r
        else:
            break
    return (str(chosen.get("rules_version") or ""), str(chosen.get("rules_path") or ""))

def verify_amendment_file(am_path: str, reg: Dict[str,Any], trusted: Dict[str,bool], attestations: List[Dict[str,Any]]) -> Dict[str,Any]:
    a = load_json(am_path)
    if str(a.get("amendment_v") or "") != "1":
        return {"ok": False, "error": "bad_amendment_v", "file": am_path}

    # msg must bind fields exactly (same rule as server)
    old_sha = str(a.get("old_rules_sha256") or "")
    new_ver = str(a.get("new_rules_version") or "")
    new_path = str(a.get("new_rules_path") or "")
    new_sigset = str(a.get("new_sigset_path") or "")
    eff = int(a.get("effective_from_checkpoint_entries") or 0)
    gset_id = str(a.get("guardian_set_id") or "")
    msg = str(a.get("msg") or "")
    prefix = f"GMF_RULES_AMEND|old:{old_sha}|new_ver:{new_ver}|new_path:{new_path}|new_sigset:{new_sigset}|eff:{eff}|set:{gset_id}|ts:"
    if not msg.startswith(prefix):
        return {"ok": False, "error": "msg_not_binding_fields", "file": am_path}

    ver = verify_msg_direct_or_attested(msg, gset_id, list(a.get("signatures") or []), reg, trusted, attestations)
    if not ver.get("ok"):
        return {"ok": False, "error": "amendment_unverified", "file": am_path, "detail": ver}

    return {"ok": True, "file": am_path, "new_rules_version": new_ver, "effective_from": eff, "verification": ver}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True, help="bundle json (from /ledger/receipt/proof_bundle)")
    ap.add_argument("--receipt-pub", required=True, help="receipt signer public key PEM path")
    ap.add_argument("--guardian-registry", default="governance/signers/registry.json")
    ap.add_argument("--transitions-dir", default="governance/signers/transitions")
    ap.add_argument("--attestations-dir", default="ledger/attestations")
    ap.add_argument("--rules-registry", default="governance/rules/registry.json")
    ap.add_argument("--amendments-dir", default="governance/rules/amendments")
    ap.add_argument("--trust-root", action="append", default=[], help="trusted root guardian_set_id (repeatable). default=registry.active_guardian_set_id")
    args = ap.parse_args()

    # bundle
    obj = load_json(args.bundle)
    if not obj.get("ok"):
        raise SystemExit("bundle ok=false")
    b = obj["bundle"]
    gov = b["governance"]
    inc = b["inclusion"]

    # trust closure
    g_reg = load_registry(args.guardian_registry)
    trust_roots = args.trust_root[:] if args.trust_root else [str(g_reg.get("active_guardian_set_id") or "guardian_set_v1")]
    trusted, accepted_transitions = build_trust_closure(g_reg, args.transitions_dir, trust_roots)
    attestations = load_attestations(args.attestations_dir)

    # verify receipt envelope
    payload = verify_receipt_envelope(b["envelope"], args.receipt_pub)

    # verify inclusion proof
    proof = inc["proof"]
    root_calc = merkle_verify(inc["leaf_sha256"], proof["siblings"], proof["directions"])
    if root_calc != inc["ledger_root_sha256"]:
        raise SystemExit("MERKLE_PROOF_ROOT_MISMATCH")

    # verify checkpoint (if present)
    cp = inc.get("checkpoint")
    cp_ver = None
    checkpoint_entries = None
    if cp:
        checkpoint_entries = int(cp.get("entries") or 0)
        cp_ver = verify_msg_direct_or_attested(str(cp.get("msg") or ""), str(cp.get("guardian_set_id") or ""), list(cp.get("signatures") or []),
                                               g_reg, trusted, attestations)
        if not cp_ver.get("ok"):
            raise SystemExit("CHECKPOINT_SIGNATURE_UNVERIFIED")
        if str(cp.get("ledger_root_sha256")) != str(inc["ledger_root_sha256"]):
            raise SystemExit("CHECKPOINT_ROOT_MISMATCH")

    # verify rules registry entries (all)
    rr = load_rules_registry(args.rules_registry)
    entry_results = []
    all_ok = True
    for e in list(rr.get("rules") or []):
        r = verify_rules_entry(e, g_reg, trusted, attestations)
        entry_results.append(r)
        if not r.get("ok"):
            all_ok = False

    # verify amendments (optional: if directory exists)
    amend_results = []
    if os.path.isdir(args.amendments_dir):
        for fp in sorted(glob.glob(os.path.join(args.amendments_dir, "*.json"))):
            amend_results.append(verify_amendment_file(fp, g_reg, trusted, attestations))

    # enforce “active rules at checkpoint” if anchor=checkpoint
    enforce = {"enforced": False}
    if checkpoint_entries is not None:
        active_ver, active_path = select_active_rules_sha(rr, checkpoint_entries)
        active_sha = compute_rules_sha_from_file(active_path) if active_path else ""
        if str(payload.get("rules_sha256")) != active_sha:
            raise SystemExit(f"ACTIVE_RULES_MISMATCH at checkpoint_entries={checkpoint_entries} active={active_ver} active_sha={active_sha} receipt_sha={payload.get('rules_sha256')}")
        enforce = {"enforced": True, "checkpoint_entries": checkpoint_entries, "active_rules_version": active_ver, "active_rules_sha256": active_sha}

    out = {
        "ok": True,
        "receipt_id": b.get("receipt_id"),
        "anchor": inc.get("anchor"),
        "merkle_root": inc.get("ledger_root_sha256"),
        "receipt_rules_sha256": payload.get("rules_sha256"),
        "checkpoint_verification": cp_ver,
        "rules_registry_all_entries_ok": all_ok,
        "rules_entries": entry_results,
        "amendments": amend_results[:50],
        "constitutional_enforcement": enforce,
        "trusted_roots": trust_roots,
        "trusted_sets_count": sum(1 for v in trusted.values() if v),
        "accepted_transitions": accepted_transitions[:50]
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
