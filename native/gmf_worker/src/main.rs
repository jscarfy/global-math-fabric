use anyhow::Context;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer};
use rand::rngs::OsRng;
use serde_json::Value;
use std::{fs, path::PathBuf, thread, time::Duration};

use gmf_receipts::{jcs_canonicalize, sha256, sha256_hex};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    relay: String, // e.g. http://host:8787

    #[arg(long, default_value_t = 30)]
    loop_seconds: u64,

    /// safety caps
    #[arg(long, default_value_t = 20)]
    max_cpu_percent: u32,

    #[arg(long, default_value_t = false)]
    wifi_only: bool,

    #[arg(long, default_value_t = false)]
    only_while_charging: bool,
}

fn key_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".gmf")
}
fn key_path() -> PathBuf {
    key_dir().join("device_seed.b64")
}

fn load_or_create_seed_b64() -> anyhow::Result<String> {
    fs::create_dir_all(key_dir())?;
    let p = key_path();
    if p.exists() {
        return Ok(fs::read_to_string(p)?.trim().to_string());
    }
    let sk = SigningKey::generate(&mut OsRng);
    let seed_b64 = B64.encode(sk.to_bytes());
    fs::write(p, &seed_b64)?;
    Ok(seed_b64)
}

fn pubkey_b64_from_seed(seed_b64: &str) -> anyhow::Result<String> {
    let seed = B64.decode(seed_b64)?;
    let sk = SigningKey::from_bytes(&seed.try_into().map_err(|_| anyhow::anyhow!("bad seed"))?);
    let pk = VerifyingKey::from(&sk);
    Ok(B64.encode(pk.to_bytes()))
}

fn device_id_from_pubkey_b64(pub_b64: &str) -> anyhow::Result<String> {
    let bytes = B64.decode(pub_b64)?;
    Ok(sha256_hex(&bytes))
}

fn sign_payload_b64(seed_b64: &str, payload: &Value) -> anyhow::Result<String> {
    let seed = B64.decode(seed_b64)?;
    let sk = SigningKey::from_bytes(&seed.try_into().map_err(|_| anyhow::anyhow!("bad seed"))?);
    let canon = jcs_canonicalize(payload);
    let msg = sha256(&canon);
    let sig: Signature = sk.sign(&msg);
    Ok(B64.encode(sig.to_bytes()))
}

fn make_consent(device_id: &str, caps: &Value) -> Value {
    serde_json::json!({
        "protocol": "gmf/consent/v1",
        "consent_payload": {
            "protocol": "gmf/consent/v1",
            "device_id": device_id,
            "granted_at": chrono::Utc::now().to_rfc3339(),
            "scope": ["compute","network"],
            "caps": caps
        }
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let seed_b64 = load_or_create_seed_b64()?;
    let pub_b64 = pubkey_b64_from_seed(&seed_b64)?;
    let device_id = device_id_from_pubkey_b64(&pub_b64)?;

    let caps = serde_json::json!({
        "max_cpu_percent": args.max_cpu_percent,
        "wifi_only": args.wifi_only,
        "only_while_charging": args.only_while_charging
    });

    // consent token JSON string (device signed)
    let mut consent = make_consent(&device_id, &caps);
    let payload = consent.get("consent_payload").unwrap().clone();
    let sig_b64 = sign_payload_b64(&seed_b64, &payload)?;
    consent.as_object_mut().unwrap().insert("device_sig_b64".into(), Value::String(sig_b64));
    let consent_token_json = serde_json::to_string(&consent)?;

    eprintln!("GMF worker device_id={device_id}");
    eprintln!("Relay={}", args.relay);

    let client = reqwest::Client::new();

    loop {
        // MVP：先送一個 “cpu_ms” claim，讓你整條鏈路跑通（後面換成 server-issued tasks）
        let claim_payload = serde_json::json!({
            "task_id": "mvp-worker-loop",
            "started_at": chrono::Utc::now().to_rfc3339(),
            "ended_at": chrono::Utc::now().to_rfc3339(),
            "metrics": { "cpu_ms": 30_000, "gpu_ms": 0, "bytes_in": 0, "bytes_out": 0 },
            "artifacts": []
        });

        let sig_b64 = sign_payload_b64(&seed_b64, &claim_payload)?;
        let body = serde_json::json!({
            "protocol": "gmf/receipt/v1",
            "consent_token_json": consent_token_json,
            "claim_payload": claim_payload,
            "device_pubkey_b64": pub_b64,
            "device_sig_b64": sig_b64
        });

        let url = format!("{}/v1/claims", args.relay.trim_end_matches('/'));
        let res = client.post(url).json(&body).send().await;
        match res {
            Ok(r) if r.status().is_success() => {
                let v: Value = r.json().await.unwrap_or(Value::Null);
                let delta = v.pointer("/receipt_payload/credits_delta_micro").and_then(|x| x.as_i64()).unwrap_or(0);
                eprintln!("SSR ok: +{delta} microcredits");
            }
            Ok(r) => {
                let t = r.text().await.unwrap_or_default();
                eprintln!("relay rejected: {} {}", r.status(), t);
            }
            Err(e) => eprintln!("relay error: {e}"),
        }

        thread::sleep(Duration::from_secs(args.loop_seconds));
    }
}
