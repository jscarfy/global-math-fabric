#!/usr/bin/env python3
import argparse, json, zipfile, base64, hashlib, io
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

ap = argparse.ArgumentParser()
ap.add_argument("--bundle-in", required=True)
ap.add_argument("--bundle-out", required=True)
ap.add_argument("--key-id", required=True)
ap.add_argument("--priv-pem", required=True)
args = ap.parse_args()

bundle_in = Path(args.bundle_in)
bundle_out = Path(args.bundle_out)

priv = serialization.load_pem_private_key(Path(args.priv_pem).read_bytes(), password=None)
if not isinstance(priv, ed25519.Ed25519PrivateKey):
    raise SystemExit("Not an Ed25519 private key")

with zipfile.ZipFile(bundle_in, "r") as z:
    manifest = z.read("manifest.json")
    wasm = z.read("module.wasm")

msg = sha256(manifest) + sha256(wasm)
sig = priv.sign(msg)

sig_json = {
    "key_id": args.key_id,
    "alg": "ed25519",
    "msg": "sha256(manifest)||sha256(wasm)",
    "manifest_sha256_b64": base64.b64encode(sha256(manifest)).decode("ascii"),
    "wasm_sha256_b64": base64.b64encode(sha256(wasm)).decode("ascii"),
    "signature_b64": base64.b64encode(sig).decode("ascii"),
}

# write new zip preserving existing files + add signature.json
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z2:
    with zipfile.ZipFile(bundle_in, "r") as z:
        for n in z.namelist():
            if n == "signature.json":
                continue
            z2.writestr(n, z.read(n))
    z2.writestr("signature.json", json.dumps(sig_json, indent=2) + "\n")

bundle_out.parent.mkdir(parents=True, exist_ok=True)
bundle_out.write_bytes(buf.getvalue())
print("Wrote signed bundle:", bundle_out)
