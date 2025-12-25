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
    report_path: PathBuf,

    /// optional: also re-check that included dates exist triple-anchors locally
    #[arg(long, default_value_t = false)]
    verify_included_days: bool,
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

fn verify_env(env: &Value, payload_key: &str) -> Result<bool> {
    let payload = env.get(payload_key).ok_or_else(|| anyhow!("missing payload key"))?;
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

fn main() -> Result<()> {
    let args = Args::parse();
    let txt = std::fs::read_to_string(&args.report_path)?;
    let env: Value = serde_json::from_str(&txt)?;

    let kind = env.get("monthly_final_payload").map(|_| "monthly")
        .or_else(|| env.get("yearly_final_payload").map(|_| "yearly"))
        .ok_or_else(|| anyhow!("not a report env"))?;

    let payload_key = if kind=="monthly" { "monthly_final_payload" } else { "yearly_final_payload" };
    let sig_ok = verify_env(&env, payload_key)?;

    println!("kind: {}", kind);
    println!("sig_ok: {}", sig_ok);

    if args.verify_included_days {
        let payload = env.get(payload_key).unwrap();
        let dates = payload.get("included_dates").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        for d in dates {
            let ds = d.as_str().unwrap_or("");
            let f = PathBuf::from("ledger/snapshots").join(format!("{ds}.final.json"));
            let a = PathBuf::from("ledger/audit").join(format!("{ds}.audit_final.json"));
            let m = PathBuf::from("ledger/meta_audit").join(format!("{ds}.meta_audit_final.json"));
            if !(f.exists() && a.exists() && m.exists()) {
                return Err(anyhow!("missing triple-anchor files for included date {}", ds));
            }
        }
        println!("included_days_triple_anchor_ok: true");
    }

    if sig_ok { std::process::exit(0); } else { std::process::exit(2); }
}
