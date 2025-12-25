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

    // expose server signing closure for final snapshot signing (msg is SHA256(payload_canon))
    let server_pubkey_b64_str = {

    let _ = write_identity_pubkey_once(&server_pubkey_b64_str);
        // reuse whatever you already put into SSR for server_pubkey_b64 if available
        // fallback: keep empty and patch manually if needed
        String::new()
    };

    let server_sign_fn: std::sync::Arc<dyn Fn(&[u8]) -> String + Send + Sync> =
        std::sync::Arc::new(move |msg: &[u8]| {
            // NOTE: patch this block to match your SSR signing implementation if it differs
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            use ed25519_dalek::Signer;
            // signing_key must be in scope in your file; if not, manually wire it.
            let sig = signing_key.sign(msg);
            B64.encode(sig.to_bytes())
        });
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


#[derive(Debug, Deserialize)]
struct LedgerDeltaQuery {
    since_unix_ms: Option<i64>,
    max_lines: Option<usize>,
}

fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn extract_ts_unix_ms(ssr: &serde_json::Value) -> Option<i64> {
    // be robust: try several keys (adjust if your SSR schema uses a specific one)
    let p = ssr.get("receipt_payload")?;
    for k in ["server_time_unix_ms","issued_at_unix_ms","time_unix_ms","ts_unix_ms","server_time_ms","issued_at_ms","ts_ms"] {
        if let Some(v) = p.get(k) {
            if let Some(i) = v.as_i64() { return Some(i); }
        }
    }
    // sometimes nested:
    if let Some(v) = ssr.get("server_time_unix_ms").and_then(|v| v.as_i64()) { return Some(v); }
    None
}


fn canonical_json_bytes(v: &serde_json::Value) -> Vec<u8> {
    fn sort(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<_> = map.keys().cloned().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), sort(&map[&k]));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(sort).collect()),
            _ => v.clone()
        }
    }
    serde_json::to_vec(&sort(v)).unwrap()
}

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn snapshot_path(date: &str) -> PathBuf {
    PathBuf::from("ledger/snapshots").join(format!("{date}.digest.json"))
}

fn inbox_path(date: &str) -> PathBuf {
    PathBuf::from("ledger/inbox").join(format!("{date}.ssr.jsonl"))
}

fn compute_snapshot(date: &str) -> Result<serde_json::Value, String> {
    let path = inbox_path(date);
    if !path.exists() {
        return Err("no such ledger day".into());
    }
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let total_bytes = bytes.len() as i64;
    let total_lines = bytes.iter().filter(|b| **b == b'\n').count() as i64
        + if bytes.len() > 0 && *bytes.last().unwrap() != b'\n' { 1 } else { 0 };

    let digest = sha256_hex(&bytes);
    Ok(serde_json::json!({
        "date": date,
        "generated_at_unix_ms": now_unix_ms(),
        "ssr_sha256": digest,
        "total_bytes": total_bytes,
        "total_lines": total_lines,
        "inbox_file": format!("ledger/inbox/{date}.ssr.jsonl")
    }))
}

fn write_snapshot(date: &str) -> Result<serde_json::Value, String> {
    let snap = compute_snapshot(date)?;
    let path = snapshot_path(date);
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&snap).unwrap()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(snap)
}


fn write_identity_pubkey_once(server_pubkey_b64: &str) -> Result<(), String> {
    let dir = PathBuf::from("ledger/identity");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("server_pubkey_b64.txt");
    if path.exists() { return Ok(()); }
    std::fs::write(&path, format!("{}\n", server_pubkey_b64)).map_err(|e| e.to_string())?;
    Ok(())
}


#[derive(Debug, Deserialize)]
struct AuditAttestReq {
    consent_token_json: serde_json::Value,
    device_pubkey_b64: String,
    attest_payload: serde_json::Value
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
        "receipt_id_sha256": "",

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



async fn ledger_snapshot(
    axum::extract::Path(date): axum::extract::Path<String>
) -> Result<(axum::http::StatusCode, String), (axum::http::StatusCode, String)> {
    if date.len() != 10 || &date[4..5] != "-" || &date[7..8] != "-" {
        return Err((axum::http::StatusCode::BAD_REQUEST, "bad date".into()));
    }
    // if snapshot exists, serve it; else generate and write it
    let path = snapshot_path(&date);
    if path.exists() {
        let txt = std::fs::read_to_string(&path).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        return Ok((axum::http::StatusCode::OK, txt));
    }
    let snap = write_snapshot(&date).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok((axum::http::StatusCode::OK, serde_json::to_string_pretty(&snap).unwrap()))
}

async fn ledger_ssr_delta(
    axum::extract::Path(date): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<LedgerDeltaQuery>
) -> Result<(axum::http::StatusCode, axum::http::HeaderMap, String), (axum::http::StatusCode, String)> {
    if date.len() != 10 || &date[4..5] != "-" || &date[7..8] != "-" {
        return Err((axum::http::StatusCode::BAD_REQUEST, "bad date".into()));
    }

    let since = q.since_unix_ms.unwrap_or(0);
    let max_lines = q.max_lines.unwrap_or(2000).clamp(1, 50_000);

    let path = inbox_path(&date);
    if !path.exists() {
        return Err((axum::http::StatusCode::NOT_FOUND, "no such ledger day".into()));
    }
    let txt = std::fs::read_to_string(&path).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut out = String::new();
    let mut kept = 0usize;
    let mut last_ts = since;

    for ln in txt.lines() {
        let t = ln.trim();
        if t.is_empty() { continue; }
        let v: serde_json::Value = match serde_json::from_str(t) { Ok(v) => v, Err(_) => continue };
        let ts = extract_ts_unix_ms(&v).unwrap_or(0);
        if ts >= since {
            out.push_str(ln);
            out.push('\n');
            kept += 1;
            if ts > last_ts { last_ts = ts; }
            if kept >= max_lines { break; }
        }
    }

    let mut headers = axum::http::HeaderMap::new();
    headers.insert("Content-Type", axum::http::HeaderValue::from_static("application/jsonl"));
    headers.insert("X-GMF-KEPT-LINES", axum::http::HeaderValue::from_str(&kept.to_string()).unwrap());
    headers.insert("X-GMF-LAST-TS-UNIX-MS", axum::http::HeaderValue::from_str(&last_ts.to_string()).unwrap());

    let may_have_more = if kept >= max_lines { "1" } else { "0" };
    headers.insert("X-GMF-MAY-HAVE-MORE", axum::http::HeaderValue::from_str(may_have_more).unwrap());
    Ok((axum::http::StatusCode::OK, headers, out))
}


fn final_snapshot_path(date: &str) -> PathBuf {
    PathBuf::from("ledger/snapshots").join(format!("{date}.final.json"))
}

fn compute_final_snapshot_payload(date: &str) -> Result<serde_json::Value, String> {
    let path = inbox_path(date);
    if !path.exists() { return Err("no such ledger day".into()); }
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let total_bytes = bytes.len() as i64;
    let total_lines = bytes.iter().filter(|b| **b == b'\n').count() as i64
        + if bytes.len() > 0 && *bytes.last().unwrap() != b'\n' { 1 } else { 0 };
    let ssr_sha256 = sha256_hex_bytes(&bytes);
    Ok(serde_json::json!({
        "date": date,
        "finalized_at_unix_ms": now_unix_ms(),
        "ssr_sha256": ssr_sha256,
        "total_bytes": total_bytes,
        "total_lines": total_lines,
        "policy": "credits_policy_v2_deterministic",
        "inbox_file": format!("ledger/inbox/{date}.ssr.jsonl")
    }))
}

// Signed envelope mirrors SSR pattern (payload + server_pubkey_b64 + server_sig_b64)
fn write_final_snapshot_once(
    date: &str,
    server_pubkey_b64: &str,
    server_sign_fn: &dyn Fn(&[u8]) -> String
) -> Result<serde_json::Value, String> {
    let out_path = final_snapshot_path(date);
    if out_path.exists() {
        let txt = std::fs::read_to_string(&out_path).map_err(|e| e.to_string())?;
        let v: serde_json::Value = serde_json::from_str(&txt).map_err(|e| e.to_string())?;
        return Ok(v);
    }

    let payload = compute_final_snapshot_payload(date)?;
    let canon = canonical_json_bytes(&payload);
    let msg = sha2::
    // compute deterministic receipt_id_sha256 from payload core (exclude receipt_id_sha256 itself)
    {
        let mut core = receipt_payload.clone();
        if let Some(obj) = core.as_object_mut() {
            obj.remove("receipt_id_sha256");
        }
        let core_canon = canonical_json_bytes(&core);
        let rid = sha256_hex_bytes(&core_canon);
        if let Some(obj) = receipt_payload.as_object_mut() {
            obj.insert("receipt_id_sha256".to_string(), serde_json::Value::String(rid));
        }
    }
Sha256::digest(&canon);
    let sig_b64 = server_sign_fn(&msg);

    let env = serde_json::json!({
        "final_payload": payload,
        "server_pubkey_b64": server_pubkey_b64,
        "server_sig_b64": sig_b64
    });

    if let Some(parent) = out_path.parent() { std::fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    let tmp = out_path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&env).unwrap()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &out_path).map_err(|e| e.to_string())?;
    Ok(env)
}


async fn ledger_finalize(
    axum::extract::Path(date): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String,String>>
) -> Result<(axum::http::StatusCode, String), (axum::http::StatusCode, String)> {
    let admin = std::env::var("GMF_ADMIN_TOKEN").unwrap_or_default();
    let tok = q.get("token").cloned().unwrap_or_default();
    if !admin.is_empty() && tok != admin {
        return Err((axum::http::StatusCode::FORBIDDEN, "forbidden".into()));
    }
    if date.len()!=10 { return Err((axum::http::StatusCode::BAD_REQUEST, "bad date".into())); }

    // NOTE: you must set server_pubkey_b64_str + server_sign_fn correctly (see previous step)
    let env = write_final_snapshot_once(&date, &server_pubkey_b64_str, server_sign_fn.as_ref())
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok((axum::http::StatusCode::OK, serde_json::to_string_pretty(&env).unwrap()))
}


async fn ledger_final(
    axum::extract::Path(date): axum::extract::Path<String>
) -> Result<(axum::http::StatusCode, String), (axum::http::StatusCode, String)> {
    if date.len() != 10 || &date[4..5] != "-" || &date[7..8] != "-" {
        return Err((axum::http::StatusCode::BAD_REQUEST, "bad date".into()));
    }
    let path = final_snapshot_path(&date);
    if !path.exists() {
        return Err((axum::http::StatusCode::NOT_FOUND, "no final snapshot".into()));
    }
    let txt = std::fs::read_to_string(&path)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((axum::http::StatusCode::OK, txt))
}


fn audit_path(date: &str) -> PathBuf {
    PathBuf::from("ledger/audit").join(format!("{date}.audit.jsonl"))
}

fn append_audit_line(date: &str, line: &serde_json::Value) -> Result<(), String> {
    let path = audit_path(date);
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    use std::io::Write;
    let mut bytes = serde_json::to_vec(line).unwrap();
    bytes.push(b'\n');
    f.write_all(&bytes).map_err(|e| e.to_string())?;
    Ok(())
}


async fn audit_attest(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::Json(req): axum::Json<AuditAttestReq>,
) -> Result<(axum::http::StatusCode, String), (axum::http::StatusCode, String)> {
    // Derive device_id from consent
    let device_id = req.consent_token_json.get("device_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();

    verify_consent(&req.consent_token_json, &req.device_pubkey_b64, &device_id)
        .map_err(|e| (axum::http::StatusCode::FORBIDDEN, e.to_string()))?;

    // Extract date + claimed final sha
    let date = req.attest_payload.get("date").and_then(|v| v.as_str())
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "missing attest_payload.date".into()))?
        .to_string();

    let claimed_sha = req.attest_payload.get("final_ssr_sha256").and_then(|v| v.as_str())
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "missing attest_payload.final_ssr_sha256".into()))?
        .to_string();

    // Require immutable final snapshot exists and matches claimed_sha
    let final_path = final_snapshot_path(&date);
    if !final_path.exists() {
        return Err((axum::http::StatusCode::PRECONDITION_FAILED, "no final snapshot".into()));
    }
    let final_txt = std::fs::read_to_string(&final_path)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let final_env: serde_json::Value = serde_json::from_str(&final_txt)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let final_sha = final_env.get("final_payload").and_then(|p| p.get("ssr_sha256")).and_then(|v| v.as_str())
        .ok_or((axum::http::StatusCode::INTERNAL_SERVER_ERROR, "bad final format".into()))?
        .to_string();

    if final_sha != claimed_sha {
        return Err((axum::http::StatusCode::BAD_REQUEST, "final sha mismatch".into()));
    }

    // Optional: require client said sig_ok true
    let sig_ok = req.attest_payload.get("final_sig_ok").and_then(|v| v.as_bool()).unwrap_or(false);
    if !sig_ok {
        return Err((axum::http::StatusCode::BAD_REQUEST, "final_sig_ok must be true".into()));
    }

    // Compose server-signed audit record
    // Note: server_sign_fn + server_pubkey_b64_str MUST be wired (from earlier steps).
    let mut payload = req.attest_payload.clone();
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("device_id".to_string(), serde_json::Value::String(device_id.clone()));
        obj.insert("device_pubkey_b64".to_string(), serde_json::Value::String(req.device_pubkey_b64.clone()));
        obj.insert("server_time_unix_ms".to_string(), serde_json::Value::Number(now_unix_ms().into()));
        obj.insert("final_server_pubkey_b64".to_string(),
            final_env.get("server_pubkey_b64").cloned().unwrap_or(serde_json::Value::Null));
        obj.insert("final_server_sig_b64".to_string(),
            final_env.get("server_sig_b64").cloned().unwrap_or(serde_json::Value::Null));
    }

    let canon = canonical_json_bytes(&payload);
    let msg = sha2::Sha256::digest(&canon);
    let sig_b64 = server_sign_fn.as_ref()(&msg);

    let audit_env = serde_json::json!({
        "audit_payload": payload,
        "server_pubkey_b64": server_pubkey_b64_str,
        "server_sig_b64": sig_b64
    });

    append_audit_line(&date, &audit_env).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok((axum::http::StatusCode::OK, serde_json::to_string_pretty(&audit_env).unwrap()))
}

async fn audit_log(
    axum::extract::Path(date): axum::extract::Path<String>
) -> Result<(axum::http::StatusCode, String), (axum::http::StatusCode, String)> {
    if date.len() != 10 || &date[4..5] != "-" || &date[7..8] != "-" {
        return Err((axum::http::StatusCode::BAD_REQUEST, "bad date".into()));
    }
    let path = audit_path(&date);
    if !path.exists() {
        return Err((axum::http::StatusCode::NOT_FOUND, "no audit log".into()));
    }
    let txt = std::fs::read_to_string(&path)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((axum::http::StatusCode::OK, txt))
}


fn audit_summary_path(date: &str) -> PathBuf {
    PathBuf::from("ledger/audit").join(format!("{date}.audit_summary.json"))
}

fn compute_audit_summary(date: &str) -> Result<serde_json::Value, String> {
    let auditp = audit_path(date);
    if !auditp.exists() { return Err("no audit log".into()); }

    let txt = std::fs::read_to_string(&auditp).map_err(|e| e.to_string())?;
    let mut total = 0i64;
    let mut sig_ok = 0i64;
    let mut sig_bad = 0i64;
    let mut parse_err = 0i64;

    let mut unique_devices = std::collections::HashSet::<String>::new();
    let mut unique_pubkeys = std::collections::HashSet::<String>::new();

    // verify each audit_env server_sig (defensive)
    for line in txt.lines() {
        let t = line.trim();
        if t.is_empty() { continue; }
        total += 1;

        let v: serde_json::Value = match serde_json::from_str(t) {
            Ok(x) => x,
            Err(_) => { parse_err += 1; continue; }
        };

        let payload = match v.get("audit_payload") { Some(p) => p, None => { parse_err += 1; continue; } };
        if let Some(d) = payload.get("device_id").and_then(|x| x.as_str()) { unique_devices.insert(d.to_string()); }
        if let Some(pk) = payload.get("device_pubkey_b64").and_then(|x| x.as_str()) { unique_pubkeys.insert(pk.to_string()); }

        // verify signature: SHA256(canonical_json_bytes(audit_payload)) signed by audit_env.server_pubkey_b64
        let pk_b64 = v.get("server_pubkey_b64").and_then(|x| x.as_str()).unwrap_or("");
        let sig_b64 = v.get("server_sig_b64").and_then(|x| x.as_str()).unwrap_or("");

        // best-effort verify; if your relay already has a generic verify fn, swap to it
        match (base64::engine::general_purpose::STANDARD.decode(pk_b64),
               base64::engine::general_purpose::STANDARD.decode(sig_b64)) {
            (Ok(pk_bytes), Ok(sig_bytes)) => {
                if pk_bytes.len()==32 && sig_bytes.len()==64 {
                    if let (Ok(pk), Ok(sig_arr)) = (
                        ed25519_dalek::VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap()),
                        <[u8;64]>::try_from(sig_bytes.as_slice())
                    ) {
                        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
                        let canon = canonical_json_bytes(payload);
                        let msg = sha2::Sha256::digest(&canon);
                        if pk.verify(&msg, &sig).is_ok() { sig_ok += 1; } else { sig_bad += 1; }
                    } else { sig_bad += 1; }
                } else { sig_bad += 1; }
            }
            _ => { sig_bad += 1; }
        }
    }

    Ok(serde_json::json!({
        "date": date,
        "generated_at_unix_ms": now_unix_ms(),
        "audit_total": total,
        "audit_parse_errors": parse_err,
        "audit_sig_ok": sig_ok,
        "audit_sig_bad": sig_bad,
        "unique_devices": unique_devices.len(),
        "unique_device_pubkeys": unique_pubkeys.len()
    }))
}

fn write_audit_summary(date: &str) -> Result<serde_json::Value, String> {
    let summary = compute_audit_summary(date)?;
    // sign summary payload (same pattern as final/snapshot)
    let canon = canonical_json_bytes(&summary);
    let msg = sha2::Sha256::digest(&canon);
    let sig_b64 = server_sign_fn.as_ref()(&msg);

    let env = serde_json::json!({
        "audit_summary_payload": summary,
        "server_pubkey_b64": server_pubkey_b64_str,
        "server_sig_b64": sig_b64
    });

    let path = audit_summary_path(date);
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&env).unwrap()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(env)
}

async fn audit_summary(
    axum::extract::Path(date): axum::extract::Path<String>
) -> Result<(axum::http::StatusCode, String), (axum::http::StatusCode, String)> {
    if date.len() != 10 || &date[4..5] != "-" || &date[7..8] != "-" {
        return Err((axum::http::StatusCode::BAD_REQUEST, "bad date".into()));
    }
    // if exists, serve; else compute+sign+write
    let path = audit_summary_path(&date);
    if path.exists() {
        let txt = std::fs::read_to_string(&path)
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        return Ok((axum::http::StatusCode::OK, txt));
    }
    let env = write_audit_summary(&date)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok((axum::http::StatusCode::OK, serde_json::to_string_pretty(&env).unwrap()))
}


fn audit_final_path(date: &str) -> PathBuf {
    PathBuf::from("ledger/audit").join(format!("{date}.audit_final.json"))
}

fn compute_audit_final_payload(date: &str) -> Result<serde_json::Value, String> {
    // require final snapshot exists (settlement anchor)
    let finalp = final_snapshot_path(date);
    if !finalp.exists() { return Err("no final snapshot".into()); }
    let final_txt = std::fs::read_to_string(&finalp).map_err(|e| e.to_string())?;
    let final_env: serde_json::Value = serde_json::from_str(&final_txt).map_err(|e| e.to_string())?;
    let final_ssr_sha256 = final_env.get("final_payload").and_then(|p| p.get("ssr_sha256")).and_then(|v| v.as_str())
        .ok_or("bad final format")?.to_string();

    let final_server_pubkey_b64 = final_env.get("server_pubkey_b64").cloned().unwrap_or(serde_json::Value::Null);
    let final_server_sig_b64 = final_env.get("server_sig_b64").cloned().unwrap_or(serde_json::Value::Null);

    // audit log bytes hash
    let ap = audit_path(date);
    if !ap.exists() { return Err("no audit log".into()); }
    let bytes = std::fs::read(&ap).map_err(|e| e.to_string())?;
    let audit_total_bytes = bytes.len() as i64;
    let audit_total_lines = bytes.iter().filter(|b| **b == b'\n').count() as i64
        + if bytes.len() > 0 && *bytes.last().unwrap() != b'\n' { 1 } else { 0 };
    let audit_log_sha256 = sha256_hex_bytes(&bytes);

    // compute summary stats (reuse compute_audit_summary which verifies audit_env signatures best-effort)
    let sum = compute_audit_summary(date)?;
    Ok(serde_json::json!({
        "date": date,
        "finalized_at_unix_ms": now_unix_ms(),
        "audit_log_sha256": audit_log_sha256,
        "audit_total_lines": audit_total_lines,
        "audit_total_bytes": audit_total_bytes,
        "audit_sig_ok": sum.get("audit_sig_ok").cloned().unwrap_or(serde_json::Value::Number(0.into())),
        "audit_sig_bad": sum.get("audit_sig_bad").cloned().unwrap_or(serde_json::Value::Number(0.into())),
        "audit_parse_errors": sum.get("audit_parse_errors").cloned().unwrap_or(serde_json::Value::Number(0.into())),
        "unique_devices": sum.get("unique_devices").cloned().unwrap_or(serde_json::Value::Number(0.into())),
        "unique_device_pubkeys": sum.get("unique_device_pubkeys").cloned().unwrap_or(serde_json::Value::Number(0.into())),
        "final_ssr_sha256": final_ssr_sha256,
        "final_server_pubkey_b64": final_server_pubkey_b64,
        "final_server_sig_b64": final_server_sig_b64
    }))
}

fn write_audit_final_once(date: &str) -> Result<serde_json::Value, String> {
    let outp = audit_final_path(date);
    if outp.exists() {
        let txt = std::fs::read_to_string(&outp).map_err(|e| e.to_string())?;
        let v: serde_json::Value = serde_json::from_str(&txt).map_err(|e| e.to_string())?;
        return Ok(v);
    }

    let payload = compute_audit_final_payload(date)?;
    let canon = canonical_json_bytes(&payload);
    let msg = sha2::Sha256::digest(&canon);
    let sig_b64 = server_sign_fn.as_ref()(&msg);

    let env = serde_json::json!({
        "audit_final_payload": payload,
        "server_pubkey_b64": server_pubkey_b64_str,
        "server_sig_b64": sig_b64
    });

    if let Some(parent) = outp.parent() { std::fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    let tmp = outp.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&env).unwrap()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &outp).map_err(|e| e.to_string())?;
    Ok(env)
}

async fn audit_final(
    axum::extract::Path(date): axum::extract::Path<String>
) -> Result<(axum::http::StatusCode, String), (axum::http::StatusCode, String)> {
    if date.len() != 10 || &date[4..5] != "-" || &date[7..8] != "-" {
        return Err((axum::http::StatusCode::BAD_REQUEST, "bad date".into()));
    }
    let path = audit_final_path(&date);
    if !path.exists() {
        return Err((axum::http::StatusCode::NOT_FOUND, "no audit_final".into()));
    }
    let txt = std::fs::read_to_string(&path)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((axum::http::StatusCode::OK, txt))
}

async fn audit_finalize(
    axum::extract::Path(date): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String,String>>
) -> Result<(axum::http::StatusCode, String), (axum::http::StatusCode, String)> {
    let admin = std::env::var("GMF_ADMIN_TOKEN").unwrap_or_default();
    let tok = q.get("token").cloned().unwrap_or_default();
    if !admin.is_empty() && tok != admin {
        return Err((axum::http::StatusCode::FORBIDDEN, "forbidden".into()));
    }
    if date.len() != 10 || &date[4..5] != "-" || &date[7..8] != "-" {
        return Err((axum::http::StatusCode::BAD_REQUEST, "bad date".into()));
    }
    let env = write_audit_final_once(&date)
        .map_err(|e| (axum::http::StatusCode::PRECONDITION_FAILED, e))?;
    Ok((axum::http::StatusCode::OK, serde_json::to_string_pretty(&env).unwrap()))
}


fn monthly_report_path(ym: &str) -> PathBuf {
    PathBuf::from("ledger/reports/monthly").join(format!("{ym}.monthly_final.json"))
}
fn yearly_report_path(y: &str) -> PathBuf {
    PathBuf::from("ledger/reports/yearly").join(format!("{y}.yearly_final.json"))
}

fn is_date_triple_ok(date: &str) -> bool {
    final_snapshot_path(date).exists()
        && audit_final_path(date).exists()
        && meta_audit_final_path(date).exists()
}

fn month_dates_utc(ym: &str) -> Result<Vec<String>, String> {
    // ym = YYYY-MM
    if ym.len()!=7 || &ym[4..5]!="-" { return Err("bad ym".into()); }
    let y: i32 = ym[0..4].parse().map_err(|_| "bad year")?;
    let m: u32 = ym[5..7].parse().map_err(|_| "bad month")?;
    if m<1 || m>12 { return Err("bad month".into()); }
    let start = chrono::NaiveDate::from_ymd_opt(y, m, 1).ok_or("bad date")?;
    let end = if m==12 {
        chrono::NaiveDate::from_ymd_opt(y+1, 1, 1).ok_or("bad end")?
    } else {
        chrono::NaiveDate::from_ymd_opt(y, m+1, 1).ok_or("bad end")?
    };
    let mut out = vec![];
    let mut d = start;
    while d < end {
        out.push(d.format("%Y-%m-%d").to_string());
        d = d.succ_opt().ok_or("date overflow")?;
    }
    Ok(out)
}

fn year_dates_utc(y: &str) -> Result<Vec<String>, String> {
    if y.len()!=4 { return Err("bad year".into()); }
    let yy: i32 = y.parse().map_err(|_| "bad year")?;
    let start = chrono::NaiveDate::from_ymd_opt(yy, 1, 1).ok_or("bad start")?;
    let end = chrono::NaiveDate::from_ymd_opt(yy+1, 1, 1).ok_or("bad end")?;
    let mut out = vec![];
    let mut d = start;
    while d < end {
        out.push(d.format("%Y-%m-%d").to_string());
        d = d.succ_opt().ok_or("date overflow")?;
    }
    Ok(out)
}

fn load_json_file(p: &PathBuf) -> Result<serde_json::Value, String> {
    let txt = std::fs::read_to_string(p).map_err(|e| e.to_string())?;
    serde_json::from_str(&txt).map_err(|e| e.to_string())
}

fn build_report_payload(kind: &str, period_id: &str, dates: Vec<String>) -> Result<serde_json::Value, String> {
    let mut included = vec![];
    let mut excluded = vec![];
    let mut finals = vec![];
    let mut audits = vec![];
    let mut metas = vec![];

    let mut sum_main_credits: i64 = 0;
    let mut sum_audit_points: i64 = 0;
    let mut main_known = true;
    let mut audit_known = true;

    for d in dates {
        if !is_date_triple_ok(&d) { excluded.push(d); continue; }
        let f = load_json_file(&final_snapshot_path(&d))?;
        let a = load_json_file(&audit_final_path(&d))?;
        let m = load_json_file(&meta_audit_final_path(&d))?;

        let fs = f.get("final_payload").and_then(|p| p.get("ssr_sha256")).and_then(|v| v.as_str()).ok_or("bad final")?;
        let al = a.get("audit_final_payload").and_then(|p| p.get("audit_log_sha256")).and_then(|v| v.as_str()).ok_or("bad audit_final")?;
        let ml = m.get("meta_audit_final_payload").and_then(|p| p.get("meta_audit_log_sha256")).and_then(|v| v.as_str()).ok_or("bad meta_audit_final")?;

        included.push(d);
        let (m_tot, a_tot) = read_canonical_totals(included.last().unwrap());
        if let Some(x) = m_tot { sum_main_credits += x; } else { main_known = false; }
        if let Some(x) = a_tot { sum_audit_points += x; } else { audit_known = false; }

        finals.push(serde_json::Value::String(fs.to_string()));
        audits.push(serde_json::Value::String(al.to_string()));
        metas.push(serde_json::Value::String(ml.to_string()));
    }

    let bindings = serde_json::json!({
        "daily_final_ssr_sha256_list": finals,
        "daily_audit_log_sha256_list": audits,
        "daily_meta_audit_log_sha256_list": metas
    });

    let roll_src = serde_json::json!({"included_dates": included, "bindings": bindings});
    let canon = canonical_json_bytes(&roll_src);
    let roll = sha2::Sha256::digest(&canon);
    let roll_hex = hex::encode(roll);

    Ok(serde_json::json!({
        "kind": kind,
        "period_id": period_id,
        "generated_at_unix_ms": now_unix_ms(),
        "included_dates": roll_src.get("included_dates").cloned().unwrap_or(serde_json::json!([])),
        "excluded_dates": excluded,
        "aggregates": {
            "days_count": roll_src.get("included_dates").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
            "sum_main_credits_micro": if main_known { serde_json::Value::Number(sum_main_credits.into()) } else { serde_json::Value::Null },
            "sum_audit_points_micro": if audit_known { serde_json::Value::Number(sum_audit_points.into()) } else { serde_json::Value::Null }
        },
        "bindings": bindings,
        "merkle_or_rollup": {
            "rollup_sha256": roll_hex,
            "method": "sha256_canon_v1"
        }
    }))
}

fn write_report_once(path: &PathBuf, payload_key: &str, payload: serde_json::Value) -> Result<serde_json::Value, String> {
    if path.exists() {
        let v = load_json_file(path)?;
        return Ok(v);
    }
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    let canon = canonical_json_bytes(&payload);
    let msg = sha2::Sha256::digest(&canon);
    let sig_b64 = server_sign_fn.as_ref()(&msg);

    let env = serde_json::json!({
        payload_key: payload,
        "server_pubkey_b64": server_pubkey_b64_str,
        "server_sig_b64": sig_b64
    });
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&env).unwrap()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(env)
}

async fn monthly_report_final(axum::extract::Path(ym): axum::extract::Path<String>)
-> Result<(axum::http::StatusCode, String), (axum::http::StatusCode, String)> {
    let p = monthly_report_path(&ym);
    if !p.exists() { return Err((axum::http::StatusCode::NOT_FOUND, "no monthly_final".into())); }
    let txt = std::fs::read_to_string(&p).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((axum::http::StatusCode::OK, txt))
}

async fn yearly_report_final(axum::extract::Path(y): axum::extract::Path<String>)
-> Result<(axum::http::StatusCode, String), (axum::http::StatusCode, String)> {
    let p = yearly_report_path(&y);
    if !p.exists() { return Err((axum::http::StatusCode::NOT_FOUND, "no yearly_final".into())); }
    let txt = std::fs::read_to_string(&p).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((axum::http::StatusCode::OK, txt))
}

async fn monthly_report_finalize(
    axum::extract::Path(ym): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String,String>>
) -> Result<(axum::http::StatusCode, String), (axum::http::StatusCode, String)> {
    let admin = std::env::var("GMF_ADMIN_TOKEN").unwrap_or_default();
    let tok = q.get("token").cloned().unwrap_or_default();
    if !admin.is_empty() && tok != admin { return Err((axum::http::StatusCode::FORBIDDEN, "forbidden".into())); }

    let dates = month_dates_utc(&ym).map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e))?;
    let payload = build_report_payload("monthly", &ym, dates).map_err(|e| (axum::http::StatusCode::PRECONDITION_FAILED, e))?;
    let env = write_report_once(&monthly_report_path(&ym), "monthly_final_payload", payload)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok((axum::http::StatusCode::OK, serde_json::to_string_pretty(&env).unwrap()))
}

async fn yearly_report_finalize(
    axum::extract::Path(y): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String,String>>
) -> Result<(axum::http::StatusCode, String), (axum::http::StatusCode, String)> {
    let admin = std::env::var("GMF_ADMIN_TOKEN").unwrap_or_default();
    let tok = q.get("token").cloned().unwrap_or_default();
    if !admin.is_empty() && tok != admin { return Err((axum::http::StatusCode::FORBIDDEN, "forbidden".into())); }

    let dates = year_dates_utc(&y).map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e))?;
    let payload = build_report_payload("yearly", &y, dates).map_err(|e| (axum::http::StatusCode::PRECONDITION_FAILED, e))?;
    let env = write_report_once(&yearly_report_path(&y), "yearly_final_payload", payload)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok((axum::http::StatusCode::OK, serde_json::to_string_pretty(&env).unwrap()))
}


fn read_canonical_totals(date: &str) -> (Option<i64>, Option<i64>) {
    // returns (main_credits_total_micro, audit_points_total_micro)
    let p = PathBuf::from("releases/settlement").join(date).join("canonical_totals.json");
    if !p.exists() { return (None, None); }
    let txt = match std::fs::read_to_string(&p) { Ok(t) => t, Err(_) => return (None, None) };
    let v: serde_json::Value = match serde_json::from_str(&txt) { Ok(x) => x, Err(_) => return (None, None) };
    let main = v.get("main_credits_total_micro").and_then(|x| x.as_i64());
    let audit = v.get("audit_points_total_micro").and_then(|x| x.as_i64());
    (main, audit)
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

    // periodic daily snapshot writer (UTC date)
    let snap_interval_secs: u64 = env::var("GMF_SNAPSHOT_INTERVAL_SECS").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(60);
    tokio::spawn(async move {
        use tokio::time::{sleep, Duration};
        loop {
            let d = Utc::now();
            let date = format!("{:04}-{:02}-{:02}", d.year(), d.month(), d.day());
            let _ = write_snapshot(&date);
            sleep(Duration::from_secs(snap_interval_secs)).await;
        }
    });
    // finalize yesterday (UTC) once inbox has been quiet for grace seconds
    let finalize_grace_secs: u64 = env::var("GMF_FINALIZE_GRACE_SECS").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(600);
    let finalize_interval_secs: u64 = env::var("GMF_FINALIZE_INTERVAL_SECS").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(60);

    let server_pubkey_b64_str2 = server_pubkey_b64_str.clone();
    let server_sign_fn2 = server_sign_fn.clone();

    tokio::spawn(async move {
        use tokio::time::{sleep, Duration};
        loop {
            let now = Utc::now();
            let y = now - chrono::Duration::days(1);
            let date = format!("{:04}-{:02}-{:02}", y.year(), y.month(), y.day());

            let inbox = inbox_path(&date);
            let finalp = final_snapshot_path(&date);

            if inbox.exists() && !finalp.exists() {
                if let Ok(md) = std::fs::metadata(&inbox) {
                    if let Ok(mtime) = md.modified() {
                        if let Ok(elapsed) = mtime.elapsed() {
                            if elapsed.as_secs() >= finalize_grace_secs {
                                let _ = write_final_snapshot_once(&date, &server_pubkey_b64_str2, server_sign_fn2.as_ref());
                            }
                        }
                    }
                }
            }

            sleep(Duration::from_secs(finalize_interval_secs)).await;
        }
    });
    // auto-finalize yesterday audit_final after audit log quiet for grace seconds (UTC)
    let audit_finalize_grace_secs: u64 = env::var("GMF_AUDIT_FINALIZE_GRACE_SECS").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(900);
    let audit_finalize_interval_secs: u64 = env::var("GMF_AUDIT_FINALIZE_INTERVAL_SECS").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(60);

    tokio::spawn(async move {
        use tokio::time::{sleep, Duration};
        loop {
            let now = Utc::now();
            let y = now - chrono::Duration::days(1);
            let date = format!("{:04}-{:02}-{:02}", y.year(), y.month(), y.day());

            let ap = audit_path(&date);
            let af = audit_final_path(&date);

            if ap.exists() && !af.exists() {
                if let Ok(md) = std::fs::metadata(&ap) {
                    if let Ok(mtime) = md.modified() {
                        if let Ok(elapsed) = mtime.elapsed() {
                            if elapsed.as_secs() >= audit_finalize_grace_secs {
                                let _ = write_audit_final_once(&date);
                            }
                        }
                    }
                }
            }
            sleep(Duration::from_secs(audit_finalize_interval_secs)).await;
        }
    });

    // auto-finalize yesterday meta_audit_final after meta_audit log quiet for grace seconds (UTC)
    let meta_finalize_grace_secs: u64 = env::var("GMF_META_AUDIT_FINALIZE_GRACE_SECS").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(900);
    let meta_finalize_interval_secs: u64 = env::var("GMF_META_AUDIT_FINALIZE_INTERVAL_SECS").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(60);

    tokio::spawn(async move {
        use tokio::time::{sleep, Duration};
        loop {
            let now = Utc::now();
            let y = now - chrono::Duration::days(1);
            let date = format!("{:04}-{:02}-{:02}", y.year(), y.month(), y.day());

            let lp = meta_audit_path(&date);
            let mf = meta_audit_final_path(&date);

            if lp.exists() && !mf.exists() {
                if let Ok(md) = std::fs::metadata(&lp) {
                    if let Ok(mtime) = md.modified() {
                        if let Ok(elapsed) = mtime.elapsed() {
                            if elapsed.as_secs() >= meta_finalize_grace_secs {
                                let _ = write_meta_audit_final_once(&date);
                            }
                        }
                    }
                }
            }
            sleep(Duration::from_secs(meta_finalize_interval_secs)).await;
        }
    });

    // auto-finalize previous month/year report anchors (write-once), after grace from period boundary
    let report_finalize_grace_secs: u64 = env::var("GMF_REPORT_FINALIZE_GRACE_SECS").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(3600);
    let report_finalize_interval_secs: u64 = env::var("GMF_REPORT_FINALIZE_INTERVAL_SECS").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(300);

    fn prev_month_id(now: chrono::DateTime<Utc>) -> String {
        let (y, m) = (now.year(), now.month());
        if m == 1 { format!("{:04}-{:02}", y-1, 12) } else { format!("{:04}-{:02}", y, m-1) }
    }
    fn prev_year_id(now: chrono::DateTime<Utc>) -> String {
        format!("{:04}", now.year()-1)
    }
    fn seconds_since_month_start(now: chrono::DateTime<Utc>) -> i64 {
        let start = chrono::NaiveDate::from_ymd_opt(now.year(), now.month(), 1).unwrap()
            .and_hms_opt(0,0,0).unwrap();
        let start = chrono::DateTime::<Utc>::from_naive_utc_and_offset(start, Utc);
        (now - start).num_seconds()
    }
    fn seconds_since_year_start(now: chrono::DateTime<Utc>) -> i64 {
        let start = chrono::NaiveDate::from_ymd_opt(now.year(), 1, 1).unwrap()
            .and_hms_opt(0,0,0).unwrap();
        let start = chrono::DateTime::<Utc>::from_naive_utc_and_offset(start, Utc);
        (now - start).num_seconds()
    }

    tokio::spawn(async move {
        use tokio::time::{sleep, Duration};
        loop {
            let now = Utc::now();

            // previous month
            if seconds_since_month_start(now) >= report_finalize_grace_secs as i64 {
                let ym = prev_month_id(now);
                let mp = monthly_report_path(&ym);
                if !mp.exists() {
                    if let Ok(dates) = month_dates_utc(&ym) {
                        if let Ok(payload) = build_report_payload("monthly", &ym, dates) {
                            let _ = write_report_once(&mp, "monthly_final_payload", payload);
                        }
                    }
                }
            }

            // previous year
            if seconds_since_year_start(now) >= report_finalize_grace_secs as i64 {
                let y = prev_year_id(now);
                let yp = yearly_report_path(&y);
                if !yp.exists() {
                    if let Ok(dates) = year_dates_utc(&y) {
                        if let Ok(payload) = build_report_payload("yearly", &y, dates) {
                            let _ = write_report_once(&yp, "yearly_final_payload", payload);
                        }
                    }
                }
            }

            sleep(Duration::from_secs(report_finalize_interval_secs)).await;
        }
    });





    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/ledger/ssr/:date", get(ledger_ssr))
        .route("/v1/ledger/ssr_delta/:date", get(ledger_ssr_delta))
        .route("/v1/ledger/snapshot/:date", get(ledger_snapshot))
        .route("/v1/ledger/finalize/:date", get(ledger_finalize))
        .route("/v1/ledger/final/:date", get(ledger_final))
        .route("/v1/audit/attest", post(audit_attest))
        .route("/v1/audit/log/:date", get(audit_log))
        .route("/v1/audit/summary/:date", get(audit_summary))
        .route("/v1/audit/final/:date", get(audit_final))
        .route("/v1/audit/finalize/:date", get(audit_finalize))
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
