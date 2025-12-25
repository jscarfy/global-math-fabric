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
    export_path: PathBuf,
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

fn verify_sig(env: &Value) -> Result<bool> {
    let payload = env.get("canonical_export_payload").ok_or_else(|| anyhow!("missing canonical_export_payload"))?;
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

fn recompute_export_rollup(payload: &Value) -> Option<String> {
    // payload includes rollup field; we recompute hash of canonical(payload_without_rollup)
    let mut p = payload.clone();
    if let Some(obj) = p.as_object_mut() {
        obj.remove("rollup");
    }
    let canon = canonical_json_bytes(&p);
    let msg = Sha256::digest(&canon);
    Some(hex::encode(msg))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let txt = std::fs::read_to_string(&args.export_path)?;
    let env: Value = serde_json::from_str(&txt)?;

    let sig_ok = verify_sig(&env)?;
    let payload = env.get("canonical_export_payload").ok_or_else(|| anyhow!("missing payload"))?;

    let got = payload.get("rollup").and_then(|r| r.get("export_rollup_sha256")).and_then(|v| v.as_str()).map(|s| s.to_string());
    let recomputed = recompute_export_rollup(payload);
    let roll_ok = match (got.as_ref(), recomputed.as_ref()) { (Some(a), Some(b)) => a == b, _ => false };

    println!("sig_ok: {}", sig_ok);
    println!("export_rollup_ok: {}", roll_ok);
    println!("export_rollup_sha256: {:?}", got);
    println!("recomputed_rollup_sha256: {:?}", recomputed);

    if sig_ok && roll_ok { std::process::exit(0); } else { std::process::exit(2); }
}
