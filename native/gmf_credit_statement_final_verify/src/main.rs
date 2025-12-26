use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::Parser;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    credit_statement_final_path: PathBuf,
    #[arg(long)]
    receipts_log_path: Option<PathBuf>,
}

fn canonical_json_bytes(v: &Value) -> Vec<u8> {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(map) => {
                let mut keys: Vec<_> = map.keys().cloned().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys { out.insert(k.clone(), sort(&map[&k])); }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            _ => v.clone(),
        }
    }
    serde_json::to_vec(&sort(v)).unwrap()
}
fn sha256_hex(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

fn main() -> Result<()> {
    let args = Args::parse();
    let env: Value = serde_json::from_str(&std::fs::read_to_string(&args.credit_statement_final_path)?)?;
    let payload = env.get("credit_statement_final_payload").ok_or_else(|| anyhow!("missing payload"))?;
    let pk_b64 = env.get("server_pubkey_b64").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("missing server_pubkey_b64"))?;
    let sig_b64 = env.get("server_sig_b64").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("missing server_sig_b64"))?;

    let pk_bytes = B64.decode(pk_b64)?;
    let pk = VerifyingKey::from_bytes(&pk_bytes.try_into().map_err(|_| anyhow!("bad pk bytes"))?)?;
    let sig_bytes = B64.decode(sig_b64)?;
    let sig = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| anyhow!("bad sig bytes"))?);

    let canon = canonical_json_bytes(payload);
    let msg = Sha256::digest(&canon);
    let sig_ok = pk.verify(&msg, &sig).is_ok();

    let mut log_ok: Option<bool> = None;
    if let Some(lp) = args.receipts_log_path {
        let bytes = std::fs::read(lp)?;
        let got = sha256_hex(&bytes);
        let exp = payload.get("receipts_log_sha256").and_then(|v| v.as_str()).unwrap_or("");
        log_ok = Some(got == exp);
    }

    println!("sig_ok: {}", sig_ok);
    println!("receipts_log_sha_matches: {:?}", log_ok);

    if sig_ok && log_ok.unwrap_or(true) { std::process::exit(0); } else { std::process::exit(2); }
}
