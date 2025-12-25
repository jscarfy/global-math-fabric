use clap::Parser;
use chrono::Utc;
use serde_json::Value;
use std::{fs, io::{BufRead, BufReader}, path::PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer};
use gmf_receipts::{jcs_canonicalize, sha256, sha256_hex, merkle_root_ct_style};

#[derive(Parser, Debug)]
struct Args {
    /// Input SSR jsonl file (each line is a ServerSignedReceipt JSON object)
    #[arg(long)]
    in_jsonl: PathBuf,

    /// Output settlement JSON path
    #[arg(long)]
    out_json: PathBuf,

    /// Date YYYY-MM-DD (default: today UTC)
    #[arg(long)]
    date: Option<String>,

    /// Previous merkle root hex (optional, for chaining)
    #[arg(long)]
    prev_root_hex: Option<String>,

    /// Policy file path to hash (credits policy pinned into settlement)
    #[arg(long)]
    policy_path: PathBuf,

    /// Server signing key (Ed25519) base64 (32 bytes)
    #[arg(long)]
    server_sk_b64: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let date = args.date.unwrap_or_else(|| Utc::now().date_naive().to_string());

    let policy_bytes = fs::read(&args.policy_path)?;
    let policy_id = sha256_hex(&policy_bytes);

    let sk_bytes = B64.decode(&args.server_sk_b64)?;
    let sk = SigningKey::from_bytes(&sk_bytes.try_into().map_err(|_| anyhow::anyhow!("bad sk"))?);
    let pk = VerifyingKey::from(&sk);
    let server_pubkey_b64 = B64.encode(pk.to_bytes());

    let f = fs::File::open(&args.in_jsonl)?;
    let r = BufReader::new(f);

    let mut entry_hashes: Vec<[u8;32]> = vec![];
    let mut entry_hash_hex: Vec<String> = vec![];

    for line in r.lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }
        let v: Value = serde_json::from_str(&line)?;
        // hash SSR payload as sha256(jcs(ssr))
        let canon = jcs_canonicalize(&v);
        let h = sha256(&canon);
        entry_hash_hex.push(hex::encode(h));
        entry_hashes.push(h);
    }

    let root = merkle_root_ct_style(&entry_hashes);
    let merkle_root_hex = hex::encode(root);

    // settlement header (signed)
    let settlement_header = serde_json::json!({
        "protocol": "gmf/settlement/v1",
        "date": date,
        "policy_id": policy_id,
        "tree_size": entry_hashes.len(),
        "merkle_root_hex": merkle_root_hex,
        "prev_merkle_root_hex": args.prev_root_hex.unwrap_or_else(|| "".to_string()),
        "entries": entry_hash_hex,
        "server_pubkey_b64": server_pubkey_b64,
    });

    let header_canon = jcs_canonicalize(&settlement_header);
    let msg = sha256(&header_canon);
    let sig: Signature = sk.sign(&msg);
    let settlement_sig_b64 = B64.encode(sig.to_bytes());

    let out = serde_json::json!({
        **settlement_header.as_object().unwrap(),
        "settlement_sig_b64": settlement_sig_b64
    });

    fs::write(&args.out_json, serde_json::to_vec_pretty(&out)?)?;
    Ok(())
}
