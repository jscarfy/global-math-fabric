use axum::{routing::{get, post}, Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    env, fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
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
    protocol: String,
    task_id: String,
    kind: String,
    params: Value,
    credit_micro_total: i64,
    replicas: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PullRequest {
    protocol: String,
    consent_token_json: String,
    device_pubkey_b64: String,
    device_sig_b64: String,
    pull_payload: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmitRequest {
    protocol: String,
    consent_token_json: String,
    device_pubkey_b64: String,
    device_sig_b64: String,
    submit_payload: Value,
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

#[derive(Debug, Deserialize)]
struct LedgerSsrQuery {
    offset_lines: Option<usize>,
    max_lines: Option<usize>,
}

fn clamp_max_lines(x: usize) -> usize {
    // hard cap to prevent abuse; tune as needed
    x.min(50_000).max(1)
}

struct AppState {
    tasks: Arc<Mutex<Vec<TaskSpec>>>,
    assigned: Arc<Mutex<HashMap<String, Lease>>>,      // lease_key "{task_id}::{device_id}"
    completed: Arc<Mutex<HashSet<String>>>,            // completed task_id
    submissions: Arc<Mutex<HashMap<String, Vec<Submission>>>>,

    // anti-dup: work_unit_id -> owner task_id
    unit_owner: Arc<Mutex<HashMap<String, String>>>,
    completed_units: Arc<Mutex<HashSet<String>>>,
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
        if spec.protocol == "gmf/task/v1" { out.push(spec); }
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

fn sha256_file_hex(p: &Path) -> anyhow::Result<String> {
    if !p.exists() { return Ok("".into()); }
    let bytes = fs::read(p)?;
    Ok(hex::encode(sha256(&bytes)))
}

fn git_rev_parse(repo: &Path, spec: &str) -> anyhow::Result<String> {
    let (code, out) = run_cmd(Command::new("git").args(["rev-parse", spec]).current_dir(repo))?;
    if code != 0 { return Err(anyhow::anyhow!("git rev-parse failed ({spec}): {out}")); }
    Ok(out.trim().to_string())
}

fn docker_build_and_hash(repo: &Path, subdir: &str, artifacts_root: &str, docker_image: &str, use_cache: bool, cmd_vec: &[String], require_artifact_hash: bool) -> anyhow::Result<Value> {
    let bash = format!(r#"
set +e
cd /workspace/{subdir}
LOG="/workspace/.gmf_build.log"
RES="/workspace/.gmf_result_core.json"
ARTROOT="/workspace/{subdir}/{artifacts_root}"

( {cache_cmd} {cmd} ) >"$LOG" 2>&1
RC=$?

BLH=$(sha256sum "$LOG" | awk '{{print $1}}')

OK=false
if [ "$RC" -eq 0 ]; then OK=true; fi

ART_COUNT=0
ART_MANIFEST_SHA=""
if {require_hash}; then
  if [ -d "$ARTROOT" ]; then
    MAN="/workspace/.gmf_artifacts.manifest"
    (cd "$ARTROOT" && find . -type f -print0 | sort -z | xargs -0 sha256sum) > "$MAN"
    ART_COUNT=$(wc -l < "$MAN" | tr -d ' ')
    ART_MANIFEST_SHA=$(sha256sum "$MAN" | awk '{{print $1}}')
  else
    OK=false
    RC=2
    ART_COUNT=0
    ART_MANIFEST_SHA=""
  fi
fi

cat > "$RES" <<EOF
{{"ok":$OK,"exit_code":$RC,"build_log_sha256":"$BLH","artifacts_root":"{artifacts_root}","artifacts_count":$ART_COUNT,"artifacts_manifest_sha256":"$ART_MANIFEST_SHA","docker_image":"{docker_image}"}}
EOF

exit 0
"#,
        subdir=subdir,
        artifacts_root=artifacts_root,
        docker_image=docker_image,
        cmd=cmd_vec.join(" "),
        cache_cmd= if use_cache { "lake exe cache get &&" } else { "" },
        require_hash= if require_artifact_hash { "true" } else { "false" },
    );

    let (code, log) = run_cmd(
        Command::new("docker")
            .arg("run").arg("--rm")
            .arg("-v").arg(format!("{}:/workspace", repo.display()))
            .arg("-w").arg("/workspace")
            .arg(docker_image)
            .arg("bash").arg("-lc").arg(bash)
    )?;

    if code != 0 {
        return Ok(serde_json::json!({
            "ok": false,
            "exit_code": 127,
            "build_log_sha256": hex::encode(sha256(log.as_bytes())),
            "artifacts_root": artifacts_root,
            "artifacts_count": 0,
            "artifacts_manifest_sha256": "",
            "docker_image": docker_image
        }));
    }

    let result_path = repo.join(".gmf_result_core.json");
    let txt = fs::read_to_string(&result_path)?;
    let v: Value = serde_json::from_str(&txt)?;
    Ok(v)
}

fn spotcheck_lean(task: &TaskSpec) -> anyhow::Result<Value> {
    let params = &task.params;
    let git_url = params.get("git_url").and_then(|v| v.as_str()).ok_or_else(|| anyhow::anyhow!("missing git_url"))?;
    let rev = params.get("rev").and_then(|v| v.as_str()).ok_or_else(|| anyhow::anyhow!("missing rev"))?;
    let subdir = params.get("subdir").and_then(|v| v.as_str()).unwrap_or("");
    let use_cache = params.get("use_mathlib_cache").and_then(|v| v.as_bool()).unwrap_or(true);
    let artifacts_root = params.get("artifacts_root").and_then(|v| v.as_str()).unwrap_or(".lake/build/lib");

    let docker_image = params.get("docker_image").and_then(|v| v.as_str())
        .unwrap_or(&env::var("GMF_LEAN_IMAGE").unwrap_or_else(|_| "leanprovercommunity/lean:latest".into()));
    let require_digest = params.get("require_digest").and_then(|v| v.as_bool()).unwrap_or(true);
    if require_digest && !docker_image.contains("@sha256:") {
        return Ok(serde_json::json!({
            "ok": false,
            "exit_code": 3,
            "build_log_sha256": hex::encode(sha256(b"docker_image_not_digest_pinned")),
            "artifacts_root": artifacts_root,
            "artifacts_count": 0,
            "artifacts_manifest_sha256": "",
            "docker_image": docker_image,
            "git_rev": "",
            "git_tree": "",
            "lean_toolchain_sha256": "",
            "lakefile_sha256": "",
            "lake_manifest_sha256": ""
        }));
    }

    let require_artifact_hash = params.get("require_artifact_hash").and_then(|v| v.as_bool()).unwrap_or(true);
    let require_source_hash = params.get("require_source_hash").and_then(|v| v.as_bool()).unwrap_or(true);

    let cmd_arr = params.get("cmd").and_then(|v| v.as_array()).cloned()
        .unwrap_or_else(|| vec![Value::String("lake".into()), Value::String("build".into())]);
    let cmd_vec: Vec<String> = cmd_arr.into_iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();

    let dir = tempdir()?;
    let repo = dir.path().join("repo");
    fs::create_dir_all(&repo)?;

    run_cmd(Command::new("git").arg("init").current_dir(&repo))?;
    run_cmd(Command::new("git").args(["remote","add","origin", git_url]).current_dir(&repo))?;
    run_cmd(Command::new("git").args(["fetch","--depth","1","origin", rev]).current_dir(&repo))?;
    run_cmd(Command::new("git").args(["checkout","FETCH_HEAD"]).current_dir(&repo))?;

    let workdir = if subdir.is_empty() { repo.clone() } else { repo.join(subdir) };

    let (git_rev, git_tree, lean_toolchain_sha256, lakefile_sha256, lake_manifest_sha256) = if require_source_hash {
        let git_rev = git_rev_parse(&repo, "HEAD")?;
        let git_tree = git_rev_parse(&repo, "HEAD^{tree}")?;
        let lean_toolchain_sha256 = sha256_file_hex(&workdir.join("lean-toolchain"))?;
        let lake_manifest_sha256 = sha256_file_hex(&workdir.join("lake-manifest.json"))?;
        let lakefile_sha256 = if workdir.join("Lakefile.lean").exists() {
            sha256_file_hex(&workdir.join("Lakefile.lean"))?
        } else {
            sha256_file_hex(&workdir.join("lakefile.lean"))?
        };
        (git_rev, git_tree, lean_toolchain_sha256, lakefile_sha256, lake_manifest_sha256)
    } else {
        ("".into(),"".into(),"".into(),"".into(),"".into())
    };

    let mut partial = docker_build_and_hash(&repo, subdir, artifacts_root, docker_image, use_cache, &cmd_vec, require_artifact_hash)?;
    partial.as_object_mut().unwrap().insert("git_rev".into(), Value::String(git_rev));
    partial.as_object_mut().unwrap().insert("git_tree".into(), Value::String(git_tree));
    partial.as_object_mut().unwrap().insert("lean_toolchain_sha256".into(), Value::String(lean_toolchain_sha256));
    partial.as_object_mut().unwrap().insert("lakefile_sha256".into(), Value::String(lakefile_sha256));
    partial.as_object_mut().unwrap().insert("lake_manifest_sha256".into(), Value::String(lake_manifest_sha256));
    Ok(partial)
}

fn normalize_result_core(task: &TaskSpec, result_core: &Value) -> Value {
    let require_artifact_hash = task.params.get("require_artifact_hash").and_then(|v| v.as_bool()).unwrap_or(true);
    let require_source_hash = task.params.get("require_source_hash").and_then(|v| v.as_bool()).unwrap_or(true);

    let ok = result_core.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let exit_code = result_core.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(9999);
    let docker_image = result_core.get("docker_image").cloned().unwrap_or(Value::String("".into()));

    let mut obj = serde_json::json!({
        "ok": ok,
        "exit_code": exit_code,
        "docker_image": docker_image
    });

    if require_artifact_hash {
        for k in ["build_log_sha256","artifacts_root","artifacts_count","artifacts_manifest_sha256"] {
            obj.as_object_mut().unwrap().insert(k.into(), result_core.get(k).cloned().unwrap_or(Value::String("".into())));
        }
    }
    if require_source_hash {
        for k in ["git_rev","git_tree","lean_toolchain_sha256","lakefile_sha256","lake_manifest_sha256"] {
            obj.as_object_mut().unwrap().insert(k.into(), result_core.get(k).cloned().unwrap_or(Value::String("".into())));
        }
    }
    obj
}

fn hard_gate_check(task: &TaskSpec, result_core: &Value) -> Option<String> {
    let require_source_hash = task.params.get("require_source_hash").and_then(|v| v.as_bool()).unwrap_or(true);
    if require_source_hash {
        let exp_rev = task.params.get("expected_git_rev").and_then(|v| v.as_str());
        let exp_tree = task.params.get("expected_git_tree").and_then(|v| v.as_str());
        if let Some(er) = exp_rev {
            let got = result_core.get("git_rev").and_then(|v| v.as_str()).unwrap_or("");
            if got != er { return Some(format!("expected_git_rev mismatch: expected={er} got={got}")); }
        }
        if let Some(et) = exp_tree {
            let got = result_core.get("git_tree").and_then(|v| v.as_str()).unwrap_or("");
            if got != et { return Some(format!("expected_git_tree mismatch: expected={et} got={got}")); }
        }
        for (ek, rk) in [
            ("expected_lean_toolchain_sha256","lean_toolchain_sha256"),
            ("expected_lakefile_sha256","lakefile_sha256"),
            ("expected_lake_manifest_sha256","lake_manifest_sha256"),
        ] {
            if let Some(ev) = task.params.get(ek).and_then(|v| v.as_str()) {
                if !ev.is_empty() {
                    let got = result_core.get(rk).and_then(|v| v.as_str()).unwrap_or("");
                    if got != ev { return Some(format!("{ek} mismatch: expected={ev} got={got}")); }
                }
            }
        }
    }

    let require_artifact_hash = task.params.get("require_artifact_hash").and_then(|v| v.as_bool()).unwrap_or(true);
    if require_artifact_hash {
        if let Some(ev) = task.params.get("expected_artifacts_manifest_sha256").and_then(|v| v.as_str()) {
            if !ev.is_empty() {
                let got = result_core.get("artifacts_manifest_sha256").and_then(|v| v.as_str()).unwrap_or("");
                if got != ev {
                    return Some(format!("expected_artifacts_manifest_sha256 mismatch: expected={ev} got={got}"));
                }
            }
        }
    }

    if let Some(di) = task.params.get("docker_image").and_then(|v| v.as_str()) {
        let got = result_core.get("docker_image").and_then(|v| v.as_str()).unwrap_or("");
        if got != di { return Some(format!("docker_image mismatch: expected={di} got={got}")); }
    }

    None
}

fn task_work_unit_id(task: &TaskSpec) -> String {
    task.params.get("work_unit_id").and_then(|v| v.as_str()).unwrap_or("").to_string()
}

async fn pull_task(state: axum::extract::State<AppState>, Json(req): Json<PullRequest>)
-> Result<Json<PullResponse>, (axum::http::StatusCode, String)> {
    if req.protocol != "gmf/task_pull/v1" { return Err((axum::http::StatusCode::BAD_REQUEST, "bad protocol".into())); }

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

    assigned.retain(|_, lease| lease.expires_at_unix > now);

    let mut unit_owner = state.unit_owner.lock().unwrap();
    let completed_units = state.completed_units.lock().unwrap();

    for t in tasks.iter() {
        if completed.contains(&t.task_id) { continue; }

        // anti-dup gating
        let unit_id = task_work_unit_id(t);
        if !unit_id.is_empty() {
            if completed_units.contains(&unit_id) {
                continue;
            }
            if let Some(owner_tid) = unit_owner.get(&unit_id) {
                if owner_tid != &t.task_id {
                    continue; // already claimed by a different task_id
                }
            } else {
                unit_owner.insert(unit_id.clone(), t.task_id.clone()); // claim it
            }
        }

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
    if req.protocol != "gmf/task_submit/v1" { return Err((axum::http::StatusCode::BAD_REQUEST, "bad protocol".into())); }

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

    let mut assigned = state.assigned.lock().unwrap();
    let lease_key = format!("{}::{}", task_id, device_id);
    if assigned.remove(&lease_key).is_none() {
        return Err((axum::http::StatusCode::CONFLICT, "no active lease for this device".into()));
    }

    let tasks = state.tasks.lock().unwrap();
    let task = tasks.iter().find(|t| t.task_id == task_id).cloned()
        .ok_or_else(|| (axum::http::StatusCode::NOT_FOUND, "unknown task_id".into()))?;

    // HARD-GATE reject
    if let Some(reason) = hard_gate_check(&task, &result_core) {
        let policy_path = PathBuf::from(env::var("GMF_POLICY_PATH").unwrap_or_else(|_| "protocol/credits/v1/CREDITS_POLICY.md".into()));
        let policy_id = read_policy_id(&policy_path).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let server_sk_b64 = env::var("GMF_SERVER_SK_B64")
            .map_err(|_| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "missing GMF_SERVER_SK_B64".into()))?;

        let unit_id = task_work_unit_id(&task);
        let receipt_payload = serde_json::json!({
            "protocol": "gmf/ssr_payload/v1",
            "policy_id": policy_id,
            "device_id": device_id,
            "task_id": task.task_id,
            "task_kind": task.kind,
            "task_params": task.params,
            "work_unit_id": unit_id,
            "credits_delta_micro": 0,
            "reason_code": "rejected_expected_source_mismatch",
            "fraud_flag": false,
            "reject_reason": reason,
            "issued_at": Utc::now().to_rfc3339()
        });

        let (server_pubkey_b64, server_sig_b64) =
            sign_ssr(&server_sk_b64, &receipt_payload)
                .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let ssr = ServerSignedReceipt{ protocol: "gmf/ssr/v1".into(), receipt_payload, server_pubkey_b64, server_sig_b64 };
        append_ssr(&ssr)?;
        return Err((axum::http::StatusCode::UNPROCESSABLE_ENTITY, serde_json::to_string(&ssr).unwrap()));
    }

    // collect submissions
    let mut subs_map = state.submissions.lock().unwrap();
    let subs = subs_map.entry(task.task_id.clone()).or_insert_with(Vec::new);
    if subs.iter().any(|s| s.device_id == device_id) {
        return Err((axum::http::StatusCode::CONFLICT, "duplicate submission".into()));
    }
    subs.push(Submission{ device_id: device_id.clone(), result_core: result_core.clone(), received_at: Utc::now().to_rfc3339() });

    let needed = task.replicas.max(1) as usize;
    if subs.len() < needed {
        return Err((axum::http::StatusCode::ACCEPTED, format!("received {}/{} submissions; waiting", subs.len(), needed)));
    }

    // bucket by normalized result_core
    let mut buckets: HashMap<String, Vec<String>> = HashMap::new();
    let mut exemplar_by_hash: HashMap<String, Value> = HashMap::new();
    for s in subs.iter() {
        let norm = normalize_result_core(&task, &s.result_core);
        let canon = jcs_canonicalize(&norm);
        let h = hex::encode(sha256(&canon));
        buckets.entry(h.clone()).or_default().push(s.device_id.clone());
        exemplar_by_hash.entry(h).or_insert(norm);
    }

    let (agree_hash, winners) = buckets.into_iter()
        .find(|(_, devs)| devs.len() >= needed)
        .ok_or_else(|| (axum::http::StatusCode::CONFLICT, "no agreement among replicas".into()))?;

    // spot-check
    let rate: f64 = env::var("GMF_SPOTCHECK_RATE").ok().and_then(|s| s.parse().ok()).unwrap_or(0.01);
    let do_spot = rand::thread_rng().gen::<f64>() < rate;
    let mut spot = serde_json::json!({"performed": do_spot});
    let mut spot_result_core: Option<Value> = None;

    if do_spot && task.kind == "lean_check" {
        match spotcheck_lean(&task) {
            Ok(rcore) => { spot["result_core"] = rcore.clone(); spot_result_core = Some(rcore); }
            Err(e) => { spot["inconclusive"] = Value::Bool(true); spot["error"] = Value::String(e.to_string()); }
        }
    }

    // mark completed (task + unit)
    {
        let mut completed = state.completed.lock().unwrap();
        completed.insert(task.task_id.clone());
    }
    let unit_id = task_work_unit_id(&task);
    if !unit_id.is_empty() {
        let mut cu = state.completed_units.lock().unwrap();
        cu.insert(unit_id.clone());
    }

    let per_device = (task.credit_micro_total / task.replicas.max(1)) as i64;

    let agreed_exemplar = exemplar_by_hash.get(&agree_hash).cloned()
        .unwrap_or_else(|| normalize_result_core(&task, &result_core));

    let fraud = if let Some(spot_core) = spot_result_core.as_ref() {
        let b = normalize_result_core(&task, spot_core);
        agreed_exemplar != b
    } else {
        false
    };

    let policy_path = PathBuf::from(env::var("GMF_POLICY_PATH").unwrap_or_else(|_| "protocol/credits/v1/CREDITS_POLICY.md".into()));
    let policy_id = read_policy_id(&policy_path).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let server_sk_b64 = env::var("GMF_SERVER_SK_B64")
        .map_err(|_| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "missing GMF_SERVER_SK_B64".into()))?;

    let unit_owner_task_id = {
        let uo = state.unit_owner.lock().unwrap();
        uo.get(&unit_id).cloned().unwrap_or("".into())
    };

    let issue_for = |dev_id: &str, delta: i64, reason: &str, fraud_flag: bool|
        -> Result<ServerSignedReceipt, (axum::http::StatusCode, String)> {
        let receipt_payload = serde_json::json!({
            "protocol": "gmf/ssr_payload/v1",
            "policy_id": policy_id,
            "device_id": dev_id,
            "task_id": task.task_id,
            "task_kind": task.kind,
            "task_params": task.params,
            "work_unit_id": unit_id,
            "unit_owner_task_id": unit_owner_task_id,
            "result_agreement_hash": agree_hash,
            "replica_winners": winners,
            "credits_delta_micro": delta,
            "reason_code": reason,
            "fraud_flag": fraud_flag,
            "spotcheck": spot,
            "normalized_agreed_result_core": agreed_exemplar,
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

    if fraud {
        for dev in winners.iter() {
            let ssr = issue_for(dev, -per_device, "spotcheck_failed", true)?;
            append_ssr(&ssr)?;
        }
        let my = issue_for(&device_id, -per_device, "spotcheck_failed", true)?;
        return Ok(Json(my));
    } else {
        let reason = if do_spot && spot_result_core.is_some() { "replica_agreement_spotcheck_ok" } else { "replica_agreement" };
        for dev in winners.iter() {
            let ssr = issue_for(dev, per_device, reason, false)?;
            append_ssr(&ssr)?;
        }
        let my = issue_for(&device_id, per_device, reason, false)?;
        return Ok(Json(my));
    }
}



async fn ledger_ssr(
    axum::extract::Path(date): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<LedgerSsrQuery>
) -> Result<(axum::http::StatusCode, axum::http::HeaderMap, Vec<u8>), (axum::http::StatusCode, String)> {
    // Strict date
    if date.len() != 10 || &date[4..5] != "-" || &date[7..8] != "-" {
        return Err((axum::http::StatusCode::BAD_REQUEST, "bad date".into()));
    }

    let path = PathBuf::from("ledger/inbox").join(format!("{date}.ssr.jsonl"));
    if !path.exists() {
        return Err((axum::http::StatusCode::NOT_FOUND, "no such ledger day".into()));
    }

    let bytes = std::fs::read(&path)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // defaults
    let offset = q.offset_lines.unwrap_or(0);
    let max_lines = clamp_max_lines(q.max_lines.unwrap_or(5000));

    // Cut by line boundaries, preserving original '\n' bytes.
    // We scan bytes and record start offsets of each line, plus end offset.
    let mut line_starts: Vec<usize> = Vec::new();
    line_starts.push(0);
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' {
            if i + 1 < bytes.len() {
                line_starts.push(i + 1);
            }
        }
    }
    let total_lines = line_starts.len();

    if offset > total_lines {
        return Err((axum::http::StatusCode::BAD_REQUEST, "offset_lines too large".into()));
    }

    let end_line = (offset + max_lines).min(total_lines);
    let start_byte = *line_starts.get(offset).unwrap_or(&bytes.len());

    // Compute end_byte: end of selected last line (inclusive of '\n' if present)
    let end_byte = if end_line >= total_lines {
        bytes.len()
    } else {
        // end_line is a start of a later line, so end_byte is that start
        *line_starts.get(end_line).unwrap_or(&bytes.len())
    };

    let chunk = bytes[start_byte..end_byte].to_vec();

    let eof = if end_line >= total_lines { "1" } else { "0" };
    let next_offset = end_line.to_string();

    let mut headers = axum::http::HeaderMap::new();
    headers.insert("Content-Type", axum::http::HeaderValue::from_static("application/octet-stream"));
    headers.insert("X-GMF-EOF", axum::http::HeaderValue::from_str(eof).unwrap());
    headers.insert("X-GMF-NEXT-OFFSET", axum::http::HeaderValue::from_str(&next_offset).unwrap());
    headers.insert("X-GMF-TOTAL-LINES", axum::http::HeaderValue::from_str(&total_lines.to_string()).unwrap());

    Ok((axum::http::StatusCode::OK, headers, chunk))
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
        unit_owner: Arc::new(Mutex::new(HashMap::new())),
        completed_units: Arc::new(Mutex::new(HashSet::new())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/ledger/ssr/:date", get(ledger_ssr))
        .route("/v1/tasks/pull", post(pull_task))
        .route("/v1/tasks/submit", post(submit_task))
        .with_state(state);

    let host = env::var("GMF_RELAY_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = env::var("GMF_RELAY_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8787);
    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    eprintln!("gmf_relay listening on http://{addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}
