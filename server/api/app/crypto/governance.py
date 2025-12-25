import json, os, base64, hashlib
from typing import Any, Dict, Tuple, List

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha256_hex_utf8(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_ed25519_pub_pem(path: str) -> Ed25519PublicKey:
    pem = open(path, "rb").read()
    k = serialization.load_pem_public_key(pem)
    if not isinstance(k, Ed25519PublicKey):
        raise ValueError("not ed25519 public key")
    return k

def verify_sigset_ed25519(msg: str, sigset: Dict[str, Any], guardian_set: Dict[str, Any]) -> Tuple[bool, int]:
    # guardian_set: {threshold, signers:[{id,pub_pem},...]}
    threshold = int(sigset.get("threshold") or guardian_set.get("threshold") or 1)
    signer_map = {}
    for s in guardian_set.get("signers", []):
        signer_map[str(s["id"])] = str(s["pub_pem"])

    ok = 0
    msg_b = msg.encode("utf-8")
    for ent in sigset.get("signatures", []):
        sid = str(ent.get("signer") or "")
        sig_b64 = str(ent.get("sig_b64") or "")
        if sid not in signer_map or not sig_b64:
            continue
        try:
            pk = load_ed25519_pub_pem(signer_map[sid])
            sig = base64.b64decode(sig_b64.encode("ascii"))
            pk.verify(sig, msg_b)
            ok += 1
        except Exception:
            continue
    return (ok >= threshold), ok

def load_governance_or_die() -> Dict[str, Any]:
    rules_path = os.environ.get("GMF_RULES_PATH", "governance/rules/v1.json")
    sigset_path = os.environ.get("GMF_RULES_SIGSET_PATH", "governance/rules/v1.sigset.json")
    registry_path = os.environ.get("GMF_GUARDIAN_REGISTRY_PATH", "governance/signers/registry.json")
    registry = load_guardian_registry(registry_path)
    # sigset declares which guardian set signs the rules
    sigset_guardian_set_id = str(load_json(sigset_path).get("guardian_set_id") or registry.get("active_guardian_set_id") or "guardian_set_v1")
    gset_path = os.environ.get("GMF_GUARDIAN_SET_PATH", None) or guardian_set_path_by_id(sigset_guardian_set_id, registry)

    rules = load_json(rules_path)
    sigset = load_json(sigset_path)
    gset = load_json(gset_path)

    rules_canon = canonical_json(rules)
    rules_sha = sha256_hex_utf8(rules_canon)

    if str(sigset.get("rules_sha256")) != rules_sha:
        raise RuntimeError(f"RULES_HASH_MISMATCH sigset={sigset.get('rules_sha256')} computed={rules_sha}")

    msg = str(sigset.get("msg") or "")
    # sanity: msg should contain rules_sha
    if rules_sha not in msg:
        raise RuntimeError("SIGSET_MSG_DOES_NOT_BIND_RULES_SHA256")

    suite = str(sigset.get("sig_suite") or "")
    if suite != "ed25519":
        raise RuntimeError(f"UNSUPPORTED_SIG_SUITE {suite}")

    ok, cnt = verify_sigset_ed25519(msg, sigset, gset)
    if not ok:
        raise RuntimeError(f"SIGSET_THRESHOLD_NOT_MET verified={cnt} threshold={sigset.get('threshold') or gset.get('threshold')}")

    return {
        "registry_path": registry_path,
        "registry": registry,
        "sigset_guardian_set_id": sigset_guardian_set_id,
        "rules_path": rules_path,
        "sigset_path": sigset_path,
        "guardian_set_path": gset_path,
        "rules": rules,
        "rules_sha256": rules_sha,
        "rules_version": rules.get("rules_version", "v1"),
        "guardian_set_id": gset.get("guardian_set_id", "guardian_set_v1"),
        "active_guardian_set_id": registry.get("active_guardian_set_id", gset.get("guardian_set_id", "guardian_set_v1")),
        "sigset": sigset,
        "guardian_set": gset,
    }


def load_guardian_registry(path: str = "governance/signers/registry.json") -> Dict[str, Any]:
    return load_json(path)

def guardian_set_path_by_id(gset_id: str, registry: Dict[str, Any]) -> str:
    sets = registry.get("sets", {}) or {}
    if gset_id not in sets:
        raise RuntimeError(f"UNKNOWN_GUARDIAN_SET_ID {gset_id}")
    return str(sets[gset_id])
