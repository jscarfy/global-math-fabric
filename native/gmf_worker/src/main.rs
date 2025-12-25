use anyhow::Context;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer};
use rand::rngs::OsRng;
use serde_json::Value;
use std::{fs, path::PathBuf, thread, time::Duration};

use gmf_receipts::{jcs_canonicalize, sha256, sha256_hex};

use num_bigint::BigUint;
use num_traits::{One, Zero};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    relay: String, // e.g. http://host:8787

    #[arg(long, default_value_t = 5)]
    loop_seconds: u64,

    /// safety caps (宣告在 consent caps；伺服端可記錄/未來可強制)
    #[arg(long, default_value_t = 20)]
    max_cpu_percent: u32,

    #[arg(long, default_value_t = false)]
    wifi_only: bool,

    #[arg(long, default_value_t = false)]
    only_while_charging: bool,
}

fn key_dir() -> PathBuf { dirs::home_dir().unwrap().join(".gmf") }
fn key_path() -> PathBuf { key_dir().join("device_seed.b64") }

fn load_or_create_seed_b64() -> anyhow::Result<String> {
    fs::create_dir_all(key_dir())?;
    let p = key_path();
    if p.exists() { return Ok(fs::read_to_string(p)?.trim().to_string()); }
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

fn fib_fast_doubling(n: u64) -> BigUint {
    fn fd(n: u64) -> (BigUint, BigUint) {
        if n == 0 { return (BigUint::zero(), BigUint::one()); }
        let (a, b) = fd(n >> 1);
        let two_b = &b << 1;
        let two_b_minus_a = if two_b >= a { two_b - &a } else { BigUint::zero() };
        let c = &a * &two_b_minus_a;
        let d = &a * &a + &b * &b;
        if (n & 1) == 0 { (c, d) } else { (d.clone(), c + d) }
    }
    fd(n).0
}

fn mod_pow(mut a: u128, mut d: u128, n: u128) -> u128 {
    let mut r: u128 = 1;
    a %= n;
    while d > 0 {
        if d & 1 == 1 { r = (r * a) % n; }
        a = (a * a) % n;
        d >>= 1;
    }
    r
}

fn is_prime_u64(n: u64) -> bool {
    if n < 2 { return false; }
    const SMALL: [u64; 12] = [2,3,5,7,11,13,17,19,23,29,31,37];
    for &p in SMALL.iter() {
        if n == p { return true; }
        if n % p == 0 { return false; }
    }
    let mut d = (n - 1) as u128;
    let mut s = 0u32;
    while (d & 1) == 0 { d >>= 1; s += 1; }
    let n128 = n as u128;
    let bases: [u64; 7] = [2, 325, 9375, 28178, 450775, 9780504, 1795265022];
    'outer: for &a0 in bases.iter() {
        let a = (a0 as u128) % n128;
        if a == 0 { continue; }
        let mut x = mod_pow(a, d, n128);
        if x == 1 || x == n128 - 1 { continue; }
        for _ in 1..s {
            x = (x * x) % n128;
            if x == n128 - 1 { continue 'outer; }
        }
        return false;
    }
    true
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let seed_b64 = load_or_create_seed_b64()?;
    let pub_b64 = pubkey_b64_from_seed(&seed_b64)?;
    let device_id = device_id_from_pubkey_b64(&pub_b64)?;
    eprintln!("GMF worker device_id={device_id}");

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

    let client = reqwest::Client::new();

    loop {
        // -------- pull task --------
        let pull_payload = serde_json::json!({
            "requested_at": chrono::Utc::now().to_rfc3339()
        });
        let pull_sig = sign_payload_b64(&seed_b64, &pull_payload)?;
        let pull_body = serde_json::json!({
            "protocol": "gmf/task_pull/v1",
            "consent_token_json": consent_token_json,
            "device_pubkey_b64": pub_b64,
            "device_sig_b64": pull_sig,
            "pull_payload": pull_payload
        });

        let pull_url = format!("{}/v1/tasks/pull", args.relay.trim_end_matches('/'));
        let pull_res = client.post(pull_url).json(&pull_body).send().await;
        let pull_json: Value = match pull_res {
            Ok(r) if r.status().is_success() => r.json().await.unwrap_or(Value::Null),
            Ok(r) => {
                eprintln!("pull rejected: {}", r.status());
                thread::sleep(Duration::from_secs(args.loop_seconds));
                continue;
            }
            Err(e) => {
                eprintln!("pull error: {e}");
                thread::sleep(Duration::from_secs(args.loop_seconds));
                continue;
            }
        };

        let task = pull_json.get("task").cloned().unwrap_or(Value::Null);
        if task.is_null() {
            eprintln!("no task; sleeping…");
            thread::sleep(Duration::from_secs(args.loop_seconds));
            continue;
        }

        let task_id = task.get("task_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let kind = task.get("kind").and_then(|v| v.as_str()).unwrap_or("unknown");
        let params = task.get("params").cloned().unwrap_or(Value::Null);

        // -------- solve --------
        let result: Value = match kind {
            "fibonacci" => {
                let n = params.get("n").and_then(|v| v.as_u64()).context("missing n")?;
                let v = fib_fast_doubling(n).to_str_radix(10);
                Value::String(v)
            }
            "is_prime_64" => {
                let x = params.get("x").and_then(|v| v.as_u64()).context("missing x")?;
                Value::Bool(is_prime_u64(x))
            }
            _ => {
                eprintln!("unknown kind={kind}; skipping");
                thread::sleep(Duration::from_secs(args.loop_seconds));
                continue;
            }
        };

        // -------- submit --------
        let submit_payload = serde_json::json!({
            "task_id": task_id,
            "result": result,
            "completed_at": chrono::Utc::now().to_rfc3339()
        });
        let submit_sig = sign_payload_b64(&seed_b64, &submit_payload)?;
        let submit_body = serde_json::json!({
            "protocol": "gmf/task_submit/v1",
            "consent_token_json": consent_token_json,
            "device_pubkey_b64": pub_b64,
            "device_sig_b64": submit_sig,
            "submit_payload": submit_payload
        });

        let submit_url = format!("{}/v1/tasks/submit", args.relay.trim_end_matches('/'));
        let sub_res = client.post(submit_url).json(&submit_body).send().await;

        match sub_res {
            Ok(r) if r.status().is_success() => {
                let ssr: Value = r.json().await.unwrap_or(Value::Null);
                let delta = ssr.pointer("/receipt_payload/credits_delta_micro").and_then(|x| x.as_i64()).unwrap_or(0);
                let task_kind = ssr.pointer("/receipt_payload/task_kind").and_then(|x| x.as_str()).unwrap_or("?");
                eprintln!("SSR ok: kind={task_kind} +{delta} microcredits");
            }
            Ok(r) => {
                let t = r.text().await.unwrap_or_default();
                eprintln!("submit rejected: {} {}", r.status(), t);
            }
            Err(e) => eprintln!("submit error: {e}"),
        }

        thread::sleep(Duration::from_secs(args.loop_seconds));
    }
}
