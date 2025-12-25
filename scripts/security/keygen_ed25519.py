#!/usr/bin/env python3
import json, argparse
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

ap = argparse.ArgumentParser()
ap.add_argument("--out-dir", default="keys")
ap.add_argument("--key-id", required=True)
args = ap.parse_args()

out = Path(args.out_dir)
out.mkdir(parents=True, exist_ok=True)

priv = ed25519.Ed25519PrivateKey.generate()
pub = priv.public_key()

priv_bytes = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
pub_bytes = pub.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

(out / f"{args.key_id}.ed25519.priv.pem").write_bytes(priv_bytes)
(out / f"{args.key_id}.ed25519.pub.json").write_text(json.dumps({
    "key_id": args.key_id,
    "alg": "ed25519",
    "public_key_raw_b64": __import__("base64").b64encode(pub_bytes).decode("ascii"),
}, indent=2) + "\n")

print("Wrote private key:", out / f"{args.key_id}.ed25519.priv.pem")
print("Wrote public  key:", out / f"{args.key_id}.ed25519.pub.json")
