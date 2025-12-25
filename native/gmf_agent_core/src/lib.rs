use anyhow::{Result, anyhow};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer};
use rand::rngs::OsRng;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Sha256, Digest};
use std::fs;
use std::path::PathBuf;

fn canon(v: &Value) -> Result<String> { Ok(serde_json::to_string(v)?) }
fn sha256_hex(s: &str) -> String { format!("{:x}", Sha256::digest(s.as_bytes())) }

fn home_dir() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn device_key_path(device_id: &str) -> PathBuf {
    let dir = home_dir().join(".gmf").join("keys");
    let _ = fs::create_dir_all(&dir);
    dir.join(format!("device_{}.ed25519.json", device_id))
}

fn load_or_create_device_key(device_id: &str) -> Result<SigningKey> {
    let path = device_key_path(device_id);
    if path.exists() {
        let txt = fs::read_to_string(&path)?;
        let v: Value = serde_json::from_str(&txt)?;
        let sk_b64 = v.get("sk_b64").and_then(|x| x.as_str()).ok_or_else(|| anyhow!("missing sk_b64"))?;
        let sk_bytes = general_purpose::STANDARD.decode(sk_b64.as_bytes())?;
        if sk_bytes.len() != 32 { return Err(anyhow!("bad sk len")); }
        let mut arr = [0u8;32];
        arr.copy_from_slice(&sk_bytes);
        return Ok(SigningKey::from_bytes(&arr));
    }
    let sk = SigningKey::generate(&mut OsRng);
    let pk: VerifyingKey = sk.verifying_key();
    let obj = serde_json::json!({
        "sk_b64": general_purpose::STANDARD.encode(sk.to_bytes()),
        "pk_b64": general_purpose::STANDARD.encode(pk.to_bytes())
    });
    fs::write(&path, serde_json::to_string_pretty(&obj)?)?;
    Ok(sk)
}

fn pubkey_b64(sk: &SigningKey) -> String {
    let pk: VerifyingKey = sk.verifying_key();
    general_purpose::STANDARD.encode(pk.to_bytes())
}

fn sign_msg_b64(sk: &SigningKey, msg: &str) -> String {
    let sig: Signature = sk.sign(msg.as_bytes());
    general_purpose::STANDARD.encode(sig.to_bytes())
}

#[derive(Debug, Deserialize)]
struct PullResp { ok: bool, job: Option<JobLease> }

#[derive(Debug, Deserialize)]
struct JobLease {
    job_id: String,
    kind: String,
    payload: Value,
    credits: i64,
    lease_id: String,
    lease_expires_at: String,
}

#[derive(Debug, Deserialize)]
struct SubmitResp {
    ok: bool,
    accepted: bool,
    reason: String,
    awarded_credits: i64,
}

fn solver(kind: &str, payload: &Value) -> Result<Value> {
    // mobile-friendly: just propose scripts; server verifies via lean_worker
    if kind == "lean_check" || kind == "audit_lean_check" {
        let candidates = vec![
            "by simp",
            "by decide",
            "by omega",
            "by aesop",
            "by
  simp",
        ];
        return Ok(serde_json::json!({ "proof_script": candidates[0] }));
    }

    if kind == "toy_math" {
        let prob = payload.get("problem").and_then(|v| v.as_str()).unwrap_or("");
        if prob == "add" {
            let a = payload.get("a").and_then(|v| v.as_i64()).ok_or_else(|| anyhow!("missing a"))?;
            let b = payload.get("b").and_then(|v| v.as_i64()).ok_or_else(|| anyhow!("missing b"))?;
            return Ok(serde_json::json!({"answer": a+b}));
        }
    }

    Err(anyhow!("no solver for kind={}", kind))
}

pub struct TickResult {
    pub had_job: bool,
    pub accepted: bool,
    pub reason: String,
    pub awarded_credits: i64,
}

pub fn register_device(api: &str, device_id: &str, platform: &str, topics: &str, ram_mb: i64, disk_mb: i64) -> Result<()> {
    let client = Client::new();
    let sk = load_or_create_device_key(device_id)?;
    let pk_b64 = pubkey_b64(&sk);

    let url = format!(
        "{}/work/devices/register?device_id={}&platform={}&has_lean=false&ram_mb={}&disk_mb={}&topics={}&pubkey_b64={}",
        api,
        urlencoding::encode(device_id),
        urlencoding::encode(platform),
        ram_mb, disk_mb,
        urlencoding::encode(topics),
        urlencoding::encode(&pk_b64),
    );
    let _ = client.post(url).send()?;
    Ok(())
}

/// one tick: pull one job (topic-matched) -> propose output -> signed submit
pub fn tick(api: &str, device_id: &str, platform: &str, topics: &str) -> Result<TickResult> {
    let client = Client::new();
    let sk = load_or_create_device_key(device_id)?;

    // heartbeat (best effort)
    let hb = format!("{}/work/devices/heartbeat?device_id={}", api, urlencoding::encode(device_id));
    let _ = client.post(hb).send();

    // pull
    let pull_url = format!(
        "{}/work/jobs/pull?device_id={}&topics={}",
        api,
        urlencoding::encode(device_id),
        urlencoding::encode(topics),
    );
    let pr: PullResp = client.get(pull_url).send()?.json()?;
    if !pr.ok { return Err(anyhow!("pull not ok")); }
    let Some(job) = pr.job else {
        return Ok(TickResult{ had_job:false, accepted:false, reason:"no_job".into(), awarded_credits:0 });
    };

    // solve
    let out = solver(&job.kind, &job.payload)?;
    let out_c = canon(&out)?;
    let out_sha = sha256_hex(&out_c);

    // device signed message
    let ts = Utc::now().to_rfc3339();
    let nonce = uuid::Uuid::new_v4().to_string();
    let device_msg = format!(
        "GMF_WORK_SUBMIT|device:{}|job:{}|lease:{}|out:{}|platform:{}|ts:{}|nonce:{}",
        device_id, job.job_id, job.lease_id, out_sha, platform, ts, nonce
    );
    let device_sig_b64 = sign_msg_b64(&sk, &device_msg);

    // submit
    let submit_url = format!(
        "{}/work/jobs/submit?device_id={}&lease_id={}&job_id={}&device_msg={}&device_sig_b64={}",
        api,
        urlencoding::encode(device_id),
        urlencoding::encode(&job.lease_id),
        urlencoding::encode(&job.job_id),
        urlencoding::encode(&device_msg),
        urlencoding::encode(&device_sig_b64),
    );
    let sr: SubmitResp = client.post(submit_url).json(&serde_json::json!({
        "device_id": device_id,
        "lease_id": job.lease_id,
        "job_id": job.job_id,
        "output": out,
        "runtime": { "platform": platform, "topics": topics, "ts": ts }
    })).send()?.json()?;

    Ok(TickResult{
        had_job:true,
        accepted:sr.accepted,
        reason:sr.reason,
        awarded_credits:sr.awarded_credits
    })
}
