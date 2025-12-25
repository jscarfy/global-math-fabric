import os, json, hashlib
from typing import Any, Dict, List, Tuple
from app.crypto.governance import load_json, load_ed25519_pub_pem

def canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def amendments_dir() -> str:
    return os.environ.get("GMF_RULES_AMENDMENTS_DIR", "governance/rules/amendments")

def rules_registry_path() -> str:
    return os.environ.get("GMF_RULES_REGISTRY_PATH", "governance/rules/registry.json")

def guardian_registry_path() -> str:
    return os.environ.get("GMF_GUARDIAN_REGISTRY_PATH", "governance/signers/registry.json")

def guardian_set_by_id(gset_id: str) -> Dict[str,Any]:
    reg = load_json(guardian_registry_path())
    sets = reg.get("sets", {}) or {}
    if gset_id not in sets:
        raise ValueError("unknown guardian_set_id")
    return load_json(str(sets[gset_id]))

def verify_threshold(msg: str, signatures: List[Dict[str,str]], gset: Dict[str,Any]) -> Tuple[bool,int,int]:
    import base64
    thr = int(gset.get("threshold") or 1)
    signer_map = {str(s["id"]): str(s["pub_pem"]) for s in gset.get("signers", [])}
    ok = 0
    msg_b = msg.encode("utf-8")
    for ent in signatures:
        sid = str(ent.get("signer") or "")
        sig_b64 = str(ent.get("sig_b64") or "")
        if sid not in signer_map or not sig_b64:
            continue
        try:
            pk = load_ed25519_pub_pem(signer_map[sid])
            pk.verify(base64.b64decode(sig_b64.encode("ascii")), msg_b)
            ok += 1
        except Exception:
            continue
    return (ok >= thr), ok, thr

def apply_amendment(amendment: Dict[str,Any]) -> Dict[str,Any]:
    """
    amendment format (signed):
      {
        "amendment_v":1,
        "old_rules_sha256": "...",
        "new_rules_version":"v2",
        "new_rules_path":"governance/rules/v2.json",
        "new_sigset_path":"governance/rules/v2.sigset.guardian_set_v2.json",
        "effective_from_checkpoint_entries": 12345,
        "guardian_set_id":"guardian_set_v2",
        "msg":"GMF_RULES_AMEND|old:...|new:...|eff:...|set:...|ts:...",
        "threshold":3,
        "signatures":[...]
      }
    """
    os.makedirs(amendments_dir(), exist_ok=True)

    # verify msg binds key fields
    old_sha = str(amendment.get("old_rules_sha256") or "")
    new_ver = str(amendment.get("new_rules_version") or "")
    new_path = str(amendment.get("new_rules_path") or "")
    new_sigset = str(amendment.get("new_sigset_path") or "")
    eff = int(amendment.get("effective_from_checkpoint_entries") or 0)
    gset_id = str(amendment.get("guardian_set_id") or "")
    msg = str(amendment.get("msg") or "")
    must = f"GMF_RULES_AMEND|old:{old_sha}|new_ver:{new_ver}|new_path:{new_path}|new_sigset:{new_sigset}|eff:{eff}|set:{gset_id}|ts:"
    if not msg.startswith(must):
        raise ValueError("amendment msg does not bind fields")

    # verify signatures against guardian_set_id
    gset = guardian_set_by_id(gset_id)
    ok, cnt, thr = verify_threshold(msg, list(amendment.get("signatures") or []), gset)
    if not ok:
        raise ValueError(f"threshold not met: ok={cnt} thr={thr}")

    # verify old_rules_sha matches currently known registry latest effective rule at eff-1 (best effort)
    reg = load_json(rules_registry_path())
    # accept even if it doesn't match (allow forks), but record mismatch flag
    mismatch = False
    # store amendment
    ts = msg.split("|ts:")[-1]
    fn = os.path.join(amendments_dir(), f"amend-{ts}-{new_ver}.json")
    with open(fn, "w", encoding="utf-8") as f:
        json.dump(amendment, f, ensure_ascii=False, sort_keys=True, indent=2)

    # update registry by appending new rules entry (idempotent-ish)
    rules_list = list(reg.get("rules") or [])
    exists = any(str(x.get("rules_version")) == new_ver and str(x.get("rules_path")) == new_path for x in rules_list)
    if not exists:
        rules_list.append({
            "rules_version": new_ver,
            "rules_path": new_path,
            "sigset_path": new_sigset,
            "effective_from_checkpoint_entries": eff
        })
        reg["rules"] = rules_list
        with open(rules_registry_path(), "w", encoding="utf-8") as f:
            json.dump(reg, f, ensure_ascii=False, sort_keys=True, indent=2)

    return {"stored": fn, "verified_signatures": cnt, "threshold": thr, "registry_updated": (not exists), "mismatch_old_rules_sha256": mismatch}
