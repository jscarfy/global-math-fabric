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
    process::Command,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use gmf_receipts::{jcs_canonicalize, sha256, sha256_hex};
use rand::Rng;
use tempfile::tempdir;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TaskSpec {
    protocol: String,                 // "gmf/task/v1"
    task_id: String,
    kind: String,
    params: Value,
    credit_micro_total: i64,
    replicas: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PullRequest {
    protocol: String,                 // "gmf/task_pull/v1"
    consent_token_json: String,
    device_pubkey_b64: String,
    device_sig_b64: String,
    pull_payload: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmitRequest {
    protocol: String,                 // "gmf/task_submit/v1"
    consent_token_json: String,
    device_pubkey_b64: String,
    device_sig_b64: String,
    submit_payload: Value,            // { task_id, result_core, completed_at }
}

#[derive(Debug, Serialize)]
struct PullResponse {
    protocol: String,
    task: Option<TaskSpec>,
    message: String,
}

#[derive(Debug, Serialize)]
struct ServerSignedReceipt {
    protocol: String,
    receipt_payload: Value,
    server_pubkey_b64: String,
    server_sig_b64: String,
}

#[derive(Debug, Clone)]
struct Lease {
    device_id: String,
    expires_at_unix: u64,
}

#[derive(Debug, Clone)]
struct Submission {
    device_id: String,
    result_core: Value,
    received_at: String,
}

#[derive(Clone)]
struct AppState {
    tasks: Arc<Mutex<Vec<TaskSpec>>>,
    assigned: Arc<Mutex<HashMap<String, Lease>>>,      // lease_key = "{task_id}::{device_id}"
    completed: Arc<Mutex<HashSet<String>>>,            // task_id done
    submissions: Arc<Mutex<HashMap<String, Vec<Submission>>>>, // task_id -> submissions
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
        if spec.protocol == "gmf/task/v1" {
            out.push(spec);
        }
    }
    Ok(out)
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

fn append_ssr(ssr: &ServerSignedReceipt) -> Result<(), (axum::http::StatusCode, String)> {
    let date = Utc::now().date_naive().to_string();
    let inbox_dir = PathBuf::from("ledger/inbox");
    fs::create_dir_all(&inbox_dir).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let path = inbox_dir.join(format!("{date}.ssr.jsonl"));
    let mut f = OpenOptions::new().create(true).append(true).open(&path)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    writeln!(f, "{}", serde_json::to_string(ssr).unwrap())
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(())
}

fn run_cmd(mut cmd: Command) -> anyhow::Result<(i32, String)> {
    let out = cmd.output()?;
    let code = out.status.code().unwrap_or(1);
    let mut s = String::new();
    s.push_str(&String::from_utf8_lossy(&out.stdout));
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((code, s))
}

fn spotcheck_lean(task: &TaskSpec) -> anyhow::Result<(bool, i32, String)> {
    let params = &task.params;
    let git_url = params.get("git_url").and_then(|v| v.as_str()).ok_or_else(|| anyhow::anyhow!("missing git_url"))?;
    let rev = params.get("rev").and_then(|v| v.as_str()).ok_or_else(|| anyhow::anyhow!("missing rev"))?;
    let subdir = params.get("subdir").and_then(|v| v.as_str()).unwrap_or("");
    let use_cache = params.get("use_mathlib_cache").and_then(|v| v.as_bool()).unwrap_or(true);

    let cmd_arr = params.get("cmd").and_then(|v| v.as_array()).cloned()
        .unwrap_or_else(|| vec![Value::String("lake".into()), Value::String("build".into())]);
    let cmd_vec: Vec<String> = cmd_arr.into_iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
    if cmd_vec.is_empty() { return Err(anyhow::anyhow!("empty cmd")); }

    let lean_image = env::var("GMF_LEAN_IMAGE").unwrap_or_else(|_| "leanprovercommunity/lean:latest".into());

    // clone into temp dir
    let dir = tempdir()?;
    let repo = dir.path().join("repo");
    fs::create_dir_all(&repo)?;

    run_cmd(Command::new("git").arg("init").current_dir(&repo))?;
    run_cmd(Command::new("git").args(["remote","add","origin", git_url]).current_dir(&repo))?;
    run_cmd(Command::new("git").args(["fetch","--depth","1","origin", rev]).current_dir(&repo))?;
    run_cmd(Command::new("git").args(["checkout","FETCH_HEAD"]).current_dir(&repo))?;

    let workdir = if subdir.is_empty() { repo.clone() } else { repo.join(subdir) };
    if !workdir.exists() {
        return Err(anyhow::anyhow!("subdir does not exist: {}", workdir.display()));
    }

    let mut bash = String::new();
    if use_cache {
        bash.push_str("lake exe cache get && ");
    }
    bash.push_str(&cmd_vec.join(" "));

    let (code, log) = run_cmd(
        Command::new("docker")
            .arg("run").arg("--rm")
            .arg("-v").arg(format!("{}:/workspace", repo.display()))
            .arg("-w").arg(format!("/workspace/{}", subdir))
            .arg(lean_image)
            .arg("bash").arg("-lc").arg(bash)
    )?;

    let ok = code == 0;
    let log_hash = hex::encode(sha256(log.as_bytes()));
    Ok((ok, code, log_hash))
}

async fn pull_task(state: axum::extract::State<AppState>, Json(req): Json<PullRequest>)
-> Result<Json<PullResponse>, (axum::http::StatusCode, String)> {
    if req.protocol != "gmf/task_pull/v1" {
        return Err((axum::http::StatusCode::BAD_REQUEST, "bad protocol".into()));
    }

    verify_device_sig_over_payload(&req.device_pubkey_b64, &req.pull_payload, &req.device_sig_b64)
        .map_err(|e| (axum::http::StatusCode::UNAUTHORIZED, e.to_string()))?;

    let device_id = device_id_from_pubkey_b64(&req.device_pubkey_b64)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;

    verify_consent(&req.consent_token_json, &req.device_pubkey_b64, &device_id)
        .map_err(|e| (axum::http::StatusCode::FORBIDDEN, e.to_string()))?;

    let now = unix_now();
    let lease_secs: u64 = env::var("GMF_TASK_LEASE_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(2400);

    let tasks = state.tasks.lock().unwrap();
    let mut assigned = state.assigned.lock().unwrap();
    let completed = state.completed.lock().unwrap();

    // cleanup expired leases
    assigned.retain(|_, lease| lease.expires_at_unix > now);

    // pick first not-completed; allow up to replicas leases; avoid same device twice
    for t in tasks.iter() {
        if completed.contains(&t.task_id) { continue; }

        let active = assigned.iter().filter(|(k, _)| k.starts_with(&(t.task_id.clone() + "::"))).count() as i64;
        if active >= t.replicas.max(1) { continue; }

        let lease_key = format!("{}::{}", t.task_id, device_id);
        if assigned.contains_key(&lease_key) { continue; }

        assigned.insert(lease_key, Lease{ device_id: device_id.clone(), expires_at_unix: now + lease_secs });

        return Ok(Json(PullResponse{
            protocol: "gmf/task_pull_resp/v1".into(),
            task: Some(t.clone()),
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

    verify_device_sig_over_payload(&req.device_pubkey_b64, &req.submit_payload, &req.device_sig_b64)
        .map_err(|e| (axum::http::StatusCode::UNAUTHORIZED, e.to_string()))?;

    let device_id = device_id_from_pubkey_b64(&req.device_pubkey_b64)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;

    verify_consent(&req.consent_token_json, &req.device_pubkey_b64, &device_id)
        .map_err(|e| (axum::http::StatusCode::FORBIDDEN, e.to_string()))?;

    let task_id = req.submit_payload.get("task_id").and_then(|v| v.as_str())
        .ok_or_else(|| (axum::http::StatusCode::BAD_REQUEST, "missing task_id".into()))?
        .to_string();

    let result_core = req.submit_payload.get("result_core")
        .ok_or_else(|| (axum::http::StatusCode::BAD_REQUEST, "missing result_core".into()))?
        .clone();

    // must have had a lease
    let mut assigned = state.assigned.lock().unwrap();
    let lease_key = format!("{}::{}", task_id, device_id);
    if assigned.remove(&lease_key).is_none() {
        return Err((axum::http::StatusCode::CONFLICT, "no active lease for this device".into()));
    }

    // locate task
    let tasks = state.tasks.lock().unwrap();
    let task = tasks.iter().find(|t| t.task_id == task_id).cloned()
        .ok_or_else(|| (axum::http::StatusCode::NOT_FOUND, "unknown task_id".into()))?;

    // append submission
    let mut subs_map = state.submissions.lock().unwrap();
    let subs = subs_map.entry(task.task_id.clone()).or_insert_with(Vec::new);

    if subs.iter().any(|s| s.device_id == device_id) {
        return Err((axum::http::StatusCode::CONFLICT, "duplicate submission".into()));
    }

    subs.push(Submission{
        device_id: device_id.clone(),
        result_core: result_core.clone(),
        received_at: Utc::now().to_rfc3339(),
    });

    // need enough replicas
    let needed = task.replicas.max(1) as usize;
    if subs.len() < needed {
        return Err((axum::http::StatusCode::ACCEPTED, format!("received {}/{} submissions; waiting", subs.len(), needed)));
    }

    // bucket by canonical hash of result_core
    let mut buckets: HashMap<String, Vec<String>> = HashMap::new();
    for s in subs.iter() {
        let canon = jcs_canonicalize(&s.result_core);
        let h = hex::encode(sha256(&canon));
        buckets.entry(h).or_default().push(s.device_id.clone());
    }

    let (agree_hash, winners) = buckets.into_iter()
        .find(|(_, devs)| devs.len() >= needed)
        .ok_or_else(|| (axum::http::StatusCode::CONFLICT, "no agreement among replicas".into()))?;

    // decide spot-check
    let rate: f64 = env::var("GMF_SPOTCHECK_RATE").ok().and_then(|s| s.parse().ok()).unwrap_or(0.01);
    let do_spot = rand::thread_rng().gen::<f64>() < rate;
    let mut spot = serde_json::json!({"performed": do_spot});

    let mut spot_ok: Option<bool> = None;
    let mut spot_exit: Option<i32> = None;
    let mut spot_log_hash: Option<String> = None;

    if do_spot && task.kind == "lean_check" {
        match spotcheck_lean(&task) {
            Ok((ok, exit_code, log_hash)) => {
                spot_ok = Some(ok);
                spot_exit = Some(exit_code);
                spot_log_hash = Some(log_hash);
                spot["ok"] = Value::Bool(ok);
                spot["exit_code"] = Value::Number(exit_code.into());
                spot["log_sha256"] = Value::String(spot_log_hash.clone().unwrap());
            }
            Err(e) => {
                // inconclusive: do not penalize
                spot["inconclusive"] = Value::Bool(true);
                spot["error"] = Value::String(e.to_string());
            }
        }
    }

    // mark completed now (immutable decision point)
    let mut completed = state.completed.lock().unwrap();
    completed.insert(task.task_id.clone());

    let per_device = (task.credit_micro_total / task.replicas.max(1)) as i64;

    // compare spot-check with agreed result (only if spot had a conclusive ok/exit_code)
    let fraud = if let (Some(ok), Some(exit_code)) = (spot_ok, spot_exit) {
        let agreed_ok = result_core.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        let agreed_exit = result_core.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(9999) as i32;
        ok != agreed_ok || exit_code != agreed_exit
    } else {
        false
    };

    let policy_path = PathBuf::from(env::var("GMF_POLICY_PATH").unwrap_or_else(|_| "protocol/credits/v1/CREDITS_POLICY.md".into()));
    let policy_id = read_policy_id(&policy_path).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let server_sk_b64 = env::var("GMF_SERVER_SK_B64")
        .map_err(|_| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "missing GMF_SERVER_SK_B64".into()))?;

    // helper: issue SSR for a specific device
    let issue_for = |dev_id: &str, delta: i64, reason: &str, fraud_flag: bool|
        -> Result<ServerSignedReceipt, (axum::http::StatusCode, String)> {
        let receipt_payload = serde_json::json!({
            "protocol": "gmf/ssr_payload/v1",
            "policy_id": policy_id,
            "device_id": dev_id,
            "task_id": task.task_id,
            "task_kind": task.kind,
            "task_params": task.params,
            "result_agreement_hash": agree_hash,
            "replica_winners": winners,
            "credits_delta_micro": delta,
            "reason_code": reason,
            "fraud_flag": fraud_flag,
            "spotcheck": spot,
            "issued_at": Utc::now().to_rfc3339()
        });
        let (server_pubkey_b64, server_sig_b64) =
            sign_ssr(&server_sk_b64, &receipt_payload)
                .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        Ok(ServerSignedReceipt{
            protocol: "gmf/ssr/v1".into(),
            receipt_payload,
            server_pubkey_b64,
            server_sig_b64,
        })
    };

    // If fraud, penalize ALL winners now (negative credits), else reward all winners now.
    if fraud {
        for dev in winners.iter() {
            let ssr = issue_for(dev, -per_device, "spotcheck_failed", true)?;
            append_ssr(&ssr)?;
        }
        // Return to caller their fraud SSR (already appended), so also just compute it again:
        let my = issue_for(&device_id, -per_device, "spotcheck_failed", true)?;
        return Ok(Json(my));
    } else {
        let reason = if do_spot && spot_ok.is_some() { "replica_agreement_spotcheck_ok" } else { "replica_agreement" };
        for dev in winners.iter() {
            let ssr = issue_for(dev, per_device, reason, false)?;
            append_ssr(&ssr)?;
        }
        let my = issue_for(&device_id, per_device, reason, false)?;
        return Ok(Json(my));
    }
}

async fn health() -> &'static str { "ok" }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let tasks_path = env::var("GMF_TASKS_JSONL").unwrap_or_else(|_| "tasks/pool/tasks.jsonl".into());
    let tasks = load_tasks_from_jsonl(&tasks_path).unwrap_or_else(|_| vec![]);
    eprintln!("Loaded {} tasks from {}", tasks.len(), tasks_path);

    let state = AppState{
        tasks: Arc::new(Mutex::new(tasks)),
        assigned: Arc::new(Mutex::new(HashMap::new())),
        completed: Arc::new(Mutex::new(HashSet::new())),
        submissions: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/tasks/pull", post(pull_task))
        .route("/v1/tasks/submit", post(submit_task))
        .with_state(state);

    let host = env::var("GMF_RELAY_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = env::var("GMF_RELAY_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8787);
    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    eprintln!("gmf_relay(spotcheck) listening on http://{addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}
