use axum::{routing::{get, post}, Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    env, fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use gmf_receipts::{jcs_canonicalize, sha256, sha256_hex};

use num_bigint::BigUint;
use num_traits::{One, Zero};

#[derive(Debug, Deserialize)]
struct ClaimEnvelope {
    protocol: String,                 // "gmf/receipt/v1"
    consent_token_json: Option<String>,
    claim_payload: Value,             // canonicalized+hashed for device sig
    device_pubkey_b64: String,
    device_sig_b64: String,           // Ed25519 over sha256(JCS(claim_payload))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TaskSpec {
    protocol: String,                 // "gmf/task/v1"
    task_id: String,
    kind: String,                     // "fibonacci" | "is_prime_64"
    params: Value,
    credit_micro: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PullRequest {
    protocol: String,                 // "gmf/task_pull/v1"
    consent_token_json: String,
    device_pubkey_b64: String,
    device_sig_b64: String,           // sig over sha256(JCS(pull_payload))
    pull_payload: Value,              // {requested_at, want_kind?}
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmitRequest {
    protocol: String,                 // "gmf/task_submit/v1"
    consent_token_json: String,
    device_pubkey_b64: String,
    device_sig_b64: String,           // sig over sha256(JCS(submit_payload))
    submit_payload: Value,            // {task_id, result, completed_at}
}

#[derive(Debug, Serialize)]
struct PullResponse {
    protocol: String,                 // "gmf/task_pull_resp/v1"
    task: Option<TaskSpec>,
    message: String,
}

#[derive(Debug, Serialize)]
struct ServerSignedReceipt {
    protocol: String,                 // "gmf/ssr/v1"
    receipt_payload: Value,           // signed below
    server_pubkey_b64: String,
    server_sig_b64: String,
}

#[derive(Debug, Clone)]
struct Lease {
    device_id: String,
    leased_at_unix: u64,
    expires_at_unix: u64,
}

#[derive(Clone)]
struct AppState {
    tasks: Arc<Mutex<Vec<TaskSpec>>>,
    assigned: Arc<Mutex<HashMap<String, Lease>>>, // task_id -> lease
    completed: Arc<Mutex<HashSet<String>>>,       // task_id done
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn verify_device_sig_over_payload(pubkey_b64: &str, payload: &Value, sig_b64: &str) -> anyhow::Result<()> {
    let pk_bytes = B64.decode(pubkey_b64)?;
    let pk = VerifyingKey::from_bytes(&pk_bytes.try_into().map_err(|_| anyhow::anyhow!("bad pk"))?)
        .map_err(|_| anyhow::anyhow!("bad pk parse"))?;
    let sig_bytes = B64.decode(sig_b64)?;
    let sig = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| anyhow::anyhow!("bad sig"))?);

    let canon = jcs_canonicalize(payload);
    let msg = sha256(&canon);
    pk.verify(&msg, &sig).map_err(|_| anyhow::anyhow!("signature invalid"))?;
    Ok(())
}

fn device_id_from_pubkey_b64(pubkey_b64: &str) -> anyhow::Result<String> {
    let pk_bytes = B64.decode(pubkey_b64)?;
    Ok(sha256_hex(&pk_bytes))
}

fn read_policy_id(policy_path: &PathBuf) -> anyhow::Result<String> {
    let bytes = fs::read(policy_path)?;
    Ok(sha256_hex(&bytes))
}

/// consent token JSON must contain consent_payload.device_id matching expected,
/// and device_sig_b64 must verify over sha256(JCS(consent_payload)).
fn verify_consent(consent_token_json: &str, device_pubkey_b64: &str, device_id_expected: &str) -> anyhow::Result<()> {
    let token_v: Value = serde_json::from_str(consent_token_json)?;
    let payload = token_v.get("consent_payload").ok_or_else(|| anyhow::anyhow!("missing consent_payload"))?;
    let sig_b64 = token_v.get("device_sig_b64").and_then(|v| v.as_str()).ok_or_else(|| anyhow::anyhow!("missing device_sig_b64"))?;

    let device_id = payload.get("device_id").and_then(|v| v.as_str()).ok_or_else(|| anyhow::anyhow!("missing device_id"))?;
    if device_id != device_id_expected {
        return Err(anyhow::anyhow!("device_id mismatch"));
    }
    verify_device_sig_over_payload(device_pubkey_b64, payload, sig_b64)?;
    Ok(())
}

fn load_tasks_from_jsonl(path: &str) -> anyhow::Result<Vec<TaskSpec>> {
    let f = fs::File::open(path)?;
    let r = BufReader::new(f);
    let mut out = vec![];
    for line in r.lines() {
        let line = line?;
        let t = line.trim();
        if t.is_empty() { continue; }
        let spec: TaskSpec = serde_json::from_str(t)?;
        if spec.protocol != "gmf/task/v1" {
            continue;
        }
        out.push(spec);
    }
    Ok(out)
}

// ---------- verifiers ----------

fn fib_fast_doubling(n: u64) -> BigUint {
    fn fd(n: u64) -> (BigUint, BigUint) {
        if n == 0 {
            return (BigUint::zero(), BigUint::one());
        }
        let (a, b) = fd(n >> 1); // (F(k), F(k+1))
        // c = F(2k) = F(k) * (2*F(k+1) - F(k))
        let two_b = &b << 1;
        let two_b_minus_a = if two_b >= a { two_b - &a } else { BigUint::zero() };
        let c = &a * &two_b_minus_a;
        // d = F(2k+1) = F(k)^2 + F(k+1)^2
        let d = &a * &a + &b * &b;
        if (n & 1) == 0 {
            (c, d)
        } else {
            (d.clone(), c + d)
        }
    }
    fd(n).0
}

fn mod_pow(mut a: u128, mut d: u128, n: u128) -> u128 {
    let mut r: u128 = 1;
    a %= n;
    while d > 0 {
        if d & 1 == 1 { r = mul_mod(r, a, n); }
        a = mul_mod(a, a, n);
        d >>= 1;
    }
    r
}

fn mul_mod(a: u128, b: u128, m: u128) -> u128 {
    // safe in u128 for mod mult of u64 operands
    (a * b) % m
}

// Deterministic Miller-Rabin for 64-bit using well-known bases.
fn is_prime_u64(n: u64) -> bool {
    if n < 2 { return false; }
    const SMALL: [u64; 12] = [2,3,5,7,11,13,17,19,23,29,31,37];
    for &p in SMALL.iter() {
        if n == p { return true; }
        if n % p == 0 { return false; }
    }
    let mut d = (n - 1) as u128;
    let mut s = 0u32;
    while (d & 1) == 0 {
        d >>= 1;
        s += 1;
    }
    let n128 = n as u128;
    // 64-bit deterministic bases
    let bases: [u64; 7] = [2, 325, 9375, 28178, 450775, 9780504, 1795265022];
    'outer: for &a0 in bases.iter() {
        let a = (a0 as u128) % n128;
        if a == 0 { continue; }
        let mut x = mod_pow(a, d, n128);
        if x == 1 || x == n128 - 1 { continue; }
        for _ in 1..s {
            x = mul_mod(x, x, n128);
            if x == n128 - 1 { continue 'outer; }
        }
        return false;
    }
    true
}

fn verify_task_result(task: &TaskSpec, result: &Value) -> anyhow::Result<()> {
    match task.kind.as_str() {
        "fibonacci" => {
            let n = task.params.get("n").and_then(|v| v.as_u64()).ok_or_else(|| anyhow::anyhow!("missing n"))?;
            let expected = fib_fast_doubling(n).to_str_radix(10);
            let got = result.as_str().ok_or_else(|| anyhow::anyhow!("result must be decimal string"))?;
            if got == expected { Ok(()) } else { Err(anyhow::anyhow!("bad fib result")) }
        }
        "is_prime_64" => {
            let x = task.params.get("x").and_then(|v| v.as_u64()).ok_or_else(|| anyhow::anyhow!("missing x"))?;
            let expected = is_prime_u64(x);
            let got = result.as_bool().ok_or_else(|| anyhow::anyhow!("result must be bool"))?;
            if got == expected { Ok(()) } else { Err(anyhow::anyhow!("bad primality result")) }
        }
        _ => Err(anyhow::anyhow!("unknown kind")),
    }
}

fn sign_ssr(server_sk_b64: &str, receipt_payload: &Value) -> anyhow::Result<(String,String)> {
    let sk_bytes = B64.decode(server_sk_b64)?;
    let sk = SigningKey::from_bytes(&sk_bytes.try_into().map_err(|_| anyhow::anyhow!("bad sk"))?);
    let pk = VerifyingKey::from(&sk);
    let server_pubkey_b64 = B64.encode(pk.to_bytes());

    let canon = jcs_canonicalize(receipt_payload);
    let msg = sha256(&canon);
    let sig: Signature = sk.sign(&msg);
    let server_sig_b64 = B64.encode(sig.to_bytes());
    Ok((server_pubkey_b64, server_sig_b64))
}

// ---------- HTTP handlers ----------

async fn pull_task(state: axum::extract::State<AppState>, Json(req): Json<PullRequest>)
-> Result<Json<PullResponse>, (axum::http::StatusCode, String)> {
    if req.protocol != "gmf/task_pull/v1" {
        return Err((axum::http::StatusCode::BAD_REQUEST, "bad protocol".into()));
    }

    // verify pull signature
    verify_device_sig_over_payload(&req.device_pubkey_b64, &req.pull_payload, &req.device_sig_b64)
        .map_err(|e| (axum::http::StatusCode::UNAUTHORIZED, e.to_string()))?;

    let device_id = device_id_from_pubkey_b64(&req.device_pubkey_b64)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;

    // consent required
    verify_consent(&req.consent_token_json, &req.device_pubkey_b64, &device_id)
        .map_err(|e| (axum::http::StatusCode::FORBIDDEN, e.to_string()))?;

    let now = unix_now();
    let lease_secs: u64 = env::var("GMF_TASK_LEASE_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(600);

    // pick first unassigned+uncompleted task
    let mut tasks = state.tasks.lock().unwrap();
    let mut assigned = state.assigned.lock().unwrap();
    let completed = state.completed.lock().unwrap();

    // cleanup expired leases
    assigned.retain(|_, lease| lease.expires_at_unix > now);

    let mut chosen: Option<TaskSpec> = None;
    for t in tasks.iter() {
        if completed.contains(&t.task_id) { continue; }
        if assigned.contains_key(&t.task_id) { continue; }
        chosen = Some(t.clone());
        break;
    }

    if let Some(task) = chosen.clone() {
        assigned.insert(task.task_id.clone(), Lease{
            device_id,
            leased_at_unix: now,
            expires_at_unix: now + lease_secs,
        });
        return Ok(Json(PullResponse{
            protocol: "gmf/task_pull_resp/v1".into(),
            task: Some(task),
            message: "ok".into(),
        }));
    }

    Ok(Json(PullResponse{
        protocol: "gmf/task_pull_resp/v1".into(),
        task: None,
        message: "no tasks available".into(),
    }))
}

async fn submit_task(state: axum::extract::State<AppState>, Json(req): Json<SubmitRequest>)
-> Result<Json<ServerSignedReceipt>, (axum::http::StatusCode, String)> {
    if req.protocol != "gmf/task_submit/v1" {
        return Err((axum::http::StatusCode::BAD_REQUEST, "bad protocol".into()));
    }

    // verify submit signature
    verify_device_sig_over_payload(&req.device_pubkey_b64, &req.submit_payload, &req.device_sig_b64)
        .map_err(|e| (axum::http::StatusCode::UNAUTHORIZED, e.to_string()))?;

    let device_id = device_id_from_pubkey_b64(&req.device_pubkey_b64)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;

    // consent required
    verify_consent(&req.consent_token_json, &req.device_pubkey_b64, &device_id)
        .map_err(|e| (axum::http::StatusCode::FORBIDDEN, e.to_string()))?;

    let task_id = req.submit_payload.get("task_id").and_then(|v| v.as_str()).ok_or_else(|| (axum::http::StatusCode::BAD_REQUEST, "missing task_id".into()))?.to_string();
    let result = req.submit_payload.get("result").ok_or_else(|| (axum::http::StatusCode::BAD_REQUEST, "missing result".into()))?.clone();

    let now = unix_now();

    let mut assigned = state.assigned.lock().unwrap();
    let mut completed = state.completed.lock().unwrap();

    // lease check
    let lease = assigned.get(&task_id).cloned().ok_or_else(|| (axum::http::StatusCode::CONFLICT, "task not leased".into()))?;
    if lease.device_id != device_id {
        return Err((axum::http::StatusCode::FORBIDDEN, "task leased to different device".into()));
    }
    if lease.expires_at_unix <= now {
        assigned.remove(&task_id);
        return Err((axum::http::StatusCode::CONFLICT, "lease expired".into()));
    }
    if completed.contains(&task_id) {
        return Err((axum::http::StatusCode::CONFLICT, "task already completed".into()));
    }

    // find task spec
    let tasks = state.tasks.lock().unwrap();
    let task = tasks.iter().find(|t| t.task_id == task_id).cloned()
        .ok_or_else(|| (axum::http::StatusCode::NOT_FOUND, "unknown task_id".into()))?;

    // verify result (fast)
    verify_task_result(&task, &result)
        .map_err(|e| (axum::http::StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;

    // issue SSR
    let policy_path = PathBuf::from(env::var("GMF_POLICY_PATH").unwrap_or_else(|_| "protocol/credits/v1/CREDITS_POLICY.md".into()));
    let policy_id = read_policy_id(&policy_path).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let server_sk_b64 = env::var("GMF_SERVER_SK_B64").map_err(|_| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "missing GMF_SERVER_SK_B64".into()))?;

    let receipt_payload = serde_json::json!({
        "protocol": "gmf/ssr_payload/v1",
        "policy_id": policy_id,
        "device_id": device_id,
        "task_id": task.task_id,
        "task_kind": task.kind,
        "task_params": task.params,
        "result": result,
        "credits_delta_micro": task.credit_micro,
        "reason_code": "verified_task",
        "issued_at": Utc::now().to_rfc3339()
    });

    let (server_pubkey_b64, server_sig_b64) = sign_ssr(&server_sk_b64, &receipt_payload)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let ssr = ServerSignedReceipt{
        protocol: "gmf/ssr/v1".into(),
        receipt_payload,
        server_pubkey_b64,
        server_sig_b64,
    };

    // append SSR to today's inbox
    let date = Utc::now().date_naive().to_string();
    let inbox_dir = PathBuf::from("ledger/inbox");
    fs::create_dir_all(&inbox_dir).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let path = inbox_dir.join(format!("{date}.ssr.jsonl"));
    let mut f = OpenOptions::new().create(true).append(true).open(&path)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    writeln!(f, "{}", serde_json::to_string(&ssr).unwrap())
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // mark completed + release lease
    completed.insert(task_id.clone());
    assigned.remove(&task_id);

    Ok(Json(ssr))
}

async fn health() -> &'static str { "ok" }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // preload tasks
    let tasks_path = env::var("GMF_TASKS_JSONL").unwrap_or_else(|_| "tasks/pool/tasks.jsonl".into());
    let tasks = load_tasks_from_jsonl(&tasks_path).unwrap_or_else(|_| vec![]);
    eprintln!("Loaded {} tasks from {}", tasks.len(), tasks_path);

    let state = AppState{
        tasks: Arc::new(Mutex::new(tasks)),
        assigned: Arc::new(Mutex::new(HashMap::new())),
        completed: Arc::new(Mutex::new(HashSet::new())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/tasks/pull", post(pull_task))
        .route("/v1/tasks/submit", post(submit_task))
        .with_state(state);

    let host = env::var("GMF_RELAY_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = env::var("GMF_RELAY_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8787);
    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    eprintln!("gmf_relay(taskd) listening on http://{addr}");

    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}
