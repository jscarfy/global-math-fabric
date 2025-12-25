import base64, hashlib, json
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def load_truststore(path: str) -> Dict[str, bytes]:
    """
    returns { key_id: raw_public_key_bytes }
    trust/public_keys.json format:
      { "trusted_keys":[ {"key_id":"...", "alg":"ed25519", "public_key_raw_b64":"..."} ] }
    """
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    out: Dict[str, bytes] = {}
    for k in doc.get("trusted_keys", []):
        if k.get("alg") != "ed25519":
            continue
        kid = k["key_id"]
        raw = base64.b64decode(k["public_key_raw_b64"])
        out[kid] = raw
    return out

def verify_bundle_ed25519(manifest: bytes, wasm: bytes, sig_doc: Dict[str, Any], trust: Dict[str, bytes]) -> None:
    key_id = sig_doc.get("key_id")
    if not key_id:
        raise ValueError("signature missing key_id")
    if sig_doc.get("alg") != "ed25519":
        raise ValueError("unsupported signature alg")
    if key_id not in trust:
        raise ValueError("untrusted key_id")

    sig = base64.b64decode(sig_doc.get("signature_b64", ""))
    msg = sha256(manifest) + sha256(wasm)

    pub = ed25519.Ed25519PublicKey.from_public_bytes(trust[key_id])
    try:
        pub.verify(sig, msg)
    except InvalidSignature as e:
        raise ValueError("invalid signature") from e
