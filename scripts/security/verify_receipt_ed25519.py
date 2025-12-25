#!/usr/bin/env python3
import argparse, json, base64, sys, hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def load_pub(path: str) -> Ed25519PublicKey:
  pem = open(path, "rb").read()
  k = serialization.load_pem_public_key(pem)
  if not isinstance(k, Ed25519PublicKey):
    raise ValueError("not ed25519 pubkey")
  return k

def verify_env(pk: Ed25519PublicKey, env: dict) -> tuple[bool, dict|None, str|None]:
  sig = base64.b64decode(env["signature_b64"])
  msg = base64.b64decode(env["payload_b64"])
  try:
    pk.verify(sig, msg)
  except Exception:
    return False, None, "signature_mismatch"

  payload = None
  try:
    payload = json.loads(msg.decode("utf-8"))
  except Exception:
    payload = None

  # optional receipt_id check (if present)
  if payload and isinstance(payload, dict) and payload.get("receipt_id"):
    rid = payload["receipt_id"]
    recomputed = hashlib.sha256(
      json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    if recomputed != rid:
      return False, payload, "receipt_id_mismatch"

  return True, payload, None

def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("--pub", required=True)
  ap.add_argument("--jsonl", required=True)
  ap.add_argument("--show-payload", action="store_true")
  args = ap.parse_args()

  pk = load_pub(args.pub)
  ok = 0
  bad = 0

  with open(args.jsonl, "r", encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
      line = line.strip()
      if not line:
        continue
      try:
        env = json.loads(line)
      except Exception:
        bad += 1
        print(f"BAD line {i}: invalid_json", file=sys.stderr)
        continue

      good, payload, reason = verify_env(pk, env)
      if good:
        ok += 1
        if args.show_payload and payload is not None:
          print(json.dumps({"line": i, "payload": payload}, ensure_ascii=False))
      else:
        bad += 1
        print(f"BAD line {i}: {reason}", file=sys.stderr)

  print(json.dumps({"ok": ok, "bad": bad}, indent=2))

if __name__ == "__main__":
  main()
