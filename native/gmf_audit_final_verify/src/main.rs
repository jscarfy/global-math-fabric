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
    relay: Option<String>,
    #[arg(long)]
    date: Option<String>,

    #[arg(long)]
    audit_final_path: Option<PathBuf>,

    #[arg(long, default_value_t = true)]
    verify_audit_log: bool,
}

fn canonical_json_bytes(v: &Value) -> Vec<u8> {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(map) => {
                let mut keys: Vec<_> = map.keys().cloned().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), sort(&map[&k]));
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            _ => v.clone(),
        }
    }
    serde_json::to_vec(&sort(v)).unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn verify_sig(env: &Value) -> Result<bool> {
    let payload = env.get("audit_final_payload").ok_or_else(|| anyhow!("missing audit_final_payload"))?;
    let pk_b64 = env.get("server_pubkey_b64").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("missing server_pubkey_b64"))?;
    let sig_b64 = env.get("server_sig_b64").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("missing server_sig_b64"))?;

    let pk_bytes = B64.decode(pk_b64)?;
    let pk = VerifyingKey::from_bytes(&pk_bytes.try_into().map_err(|_| anyhow!("bad pk bytes"))?)
        .map_err(|_| anyhow!("bad pk"))?;

    let sig_bytes = B64.decode(sig_b64)?;
    let sig = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| anyhow!("bad sig bytes"))?);

    let canon = canonical_json_bytes(payload);
    let msg = Sha256::digest(&canon);

    Ok(pk.verify(&msg, &sig).is_ok())
}

async fn fetch_audit_final(relay: &str, date: &str) -> Result<Value> {
    let url = format!("{}/v1/audit/final/{}", relay.trim_end_matches('/'), date);
    let txt = reqwest::get(&url).await?.text().await?;
    Ok(serde_json::from_str(&txt)?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let env: Value = if let (Some(relay), Some(date)) = (args.relay.as_deref(), args.date.as_deref()) {
        fetch_audit_final(relay, date).await?
    } else if let Some(p) = args.audit_final_path.as_deref() {
        serde_json::from_str(&std::fs::read_to_string(p)?)?
    } else {
        return Err(anyhow!("provide either --relay+--date or --audit-final-path"));
    };

    let sig_ok = verify_sig(&env)?;
    let date = env.get("audit_final_payload").and_then(|p| p.get("date")).and_then(|v| v.as_str()).unwrap_or("UNKNOWN").to_string();

    let mut audit_log_ok: Option<bool> = None;
    if args.verify_audit_log {
        let expected = env.get("audit_final_payload").and_then(|p| p.get("audit_log_sha256")).and_then(|v| v.as_str()).map(|s| s.to_string());
        if let Some(exp) = expected {
            let audit_log = PathBuf::from("ledger/audit").join(format!("{}.audit.jsonl", date));
            if audit_log.exists() {
                let bytes = std::fs::read(audit_log)?;
                let got = sha256_hex(&bytes);
                audit_log_ok = Some(got == exp);
            }
        }
    }

    println!("date: {}", date);
    println!("audit_final_sig_ok: {}", sig_ok);
    println!("audit_log_sha_matches_audit_final: {:?}", audit_log_ok);

    if sig_ok && audit_log_ok.unwrap_or(true) {
        std::process::exit(0);
    } else {
        std::process::exit(2);
    }
}
