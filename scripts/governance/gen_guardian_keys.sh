#!/usr/bin/env bash
set -euo pipefail
N="${1:-3}"
OUT_DIR="governance/vault"
PUB_DIR="governance/signers"
mkdir -p "$OUT_DIR" "$PUB_DIR"
for i in $(seq 1 "$N"); do
  PRIV="$OUT_DIR/guardian-$i.ed25519.priv.pem"
  PUB="$PUB_DIR/guardian-$i.ed25519.pub.pem"
  if [ -f "$PRIV" ]; then
    echo "exists: $PRIV"
    continue
  fi
  openssl genpkey -algorithm Ed25519 -out "$PRIV"
  openssl pkey -in "$PRIV" -pubout -out "$PUB"
  echo "generated guardian-$i"
done
