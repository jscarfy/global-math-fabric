import base64, json, os, hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def load_receipt_signing_private_key() -> tuple[str, ed25519.Ed25519PrivateKey]:
    key_id = os.environ.get("GMF_RECEIPT_KEY_ID", "receipt-dev")
    pem_path = os.environ.get("GMF_RECEIPT_PRIVATE_PEM", "keys/receipt-dev.ed25519.priv.pem")
    with open(pem_path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(priv, ed25519.Ed25519PrivateKey):
        raise RuntimeError("receipt private key is not ed25519")
    return key_id, priv

def sign_receipt(body: dict) -> tuple[str, str]:
    key_id, priv = load_receipt_signing_private_key()
    canon = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = priv.sign(sha256(canon))
    return key_id, base64.b64encode(sig).decode("ascii")
