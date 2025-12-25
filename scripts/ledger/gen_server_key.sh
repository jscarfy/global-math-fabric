#!/usr/bin/env bash
set -euo pipefail
# outputs server keys (DO NOT COMMIT private key)
cargo run -q --manifest-path native/gmf_receipts/Cargo.toml --example none 2>/dev/null || true

# Use rust one-liner via cargo script-like: compile small temp
cat > /tmp/gmf_genkey.rs <<'RS'
use gmf_receipts::generate_device_keypair_b64;
fn main(){ let (pk,sk)=generate_device_keypair_b64(); println!("SERVER_PUB_B64={}",pk); println!("SERVER_SK_B64={}",sk); }
RS
rustc /tmp/gmf_genkey.rs -L native/target/debug/deps -o /tmp/gmf_genkey 2>/dev/null || true
echo "If rustc fails, run: cargo build -p gmf_receipts (native workspace) then rerun."
