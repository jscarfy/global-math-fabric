import json, os, base64
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def canonical_json_bytes(obj: Any) -> bytes:
    # stable across platforms: sorted keys, compact separators, UTF-8
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def load_ed25519_private_key_pem(path: str) -> Ed25519PrivateKey:
    pem = open(path, "rb").read()
    k = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(k, Ed25519PrivateKey):
        raise ValueError("not ed25519 private key")
    return k

def load_ed25519_public_key_pem(path: str) -> Ed25519PublicKey:
    pem = open(path, "rb").read()
    k = serialization.load_pem_public_key(pem)
    if not isinstance(k, Ed25519PublicKey):
        raise ValueError("not ed25519 public key")
    return k

def sign_receipt(payload: Dict[str, Any]) -> Tuple[str, str, str]:
    key_id = os.environ.get("GMF_RECEIPT_KEY_ID", "receipt-dev")
    priv_path = os.environ.get("GMF_RECEIPT_PRIVATE_PEM", "keys/receipt-dev.ed25519.priv.pem")
    sk = load_ed25519_private_key_pem(priv_path)
    msg = canonical_json_bytes(payload)
    sig = sk.sign(msg)
    # base64 for transport
    return key_id, base64.b64encode(sig).decode("ascii"), base64.b64encode(msg).decode("ascii")

def verify_receipt(payload_b64: str, sig_b64: str, pub_pem_path: str) -> bool:
    import base64
    pk = load_ed25519_public_key_pem(pub_pem_path)
    msg = base64.b64decode(payload_b64.encode("ascii"))
    sig = base64.b64decode(sig_b64.encode("ascii"))
    try:
        pk.verify(sig, msg)
        return True
    except Exception:
        return False

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
