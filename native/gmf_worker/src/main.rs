use anyhow::{Context, anyhow};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer};
use rand::rngs::OsRng;
use serde_json::Value;
use std::{fs, path::PathBuf, thread, time::Duration, process::Command};

use gmf_receipts::{jcs_canonicalize, sha256, sha256_hex};
use tempfile::tempdir;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    relay: String,

    #[arg(long, default_value_t = 10)]
    loop_seconds: u64,

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
    let sk = SigningKey::from_bytes(&seed.try_into().map_err(|_| anyhow!("bad seed"))?);
    let pk = VerifyingKey::from(&sk);
    Ok(B64.encode(pk.to_bytes()))
}

fn device_id_from_pubkey_b64(pub_b64: &str) -> anyhow::Result<String> {
    let bytes = B64.decode(pub_b64)?;
    Ok(sha256_hex(&bytes))
}

fn sign_payload_b64(seed_b64: &str, payload: &Value) -> anyhow::Result<String> {
    let seed = B64.decode(seed_b64)?;
    let sk = SigningKey::from_bytes(&seed.try_into().map_err(|_| anyhow!("bad seed"))?);
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

fn run_cmd(mut cmd: Command) -> anyhow::Result<(i32, String)> {
    let out = cmd.output().context("spawn command")?;
    let code = out.status.code().unwrap_or(1);
    let mut s = String::new();
    s.push_str(&String::from_utf8_lossy(&out.stdout));
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((code, s))
}

/// Docker script writes /workspace/.gmf_result_core.json
fn solve_lean_check(task: &Value) -> anyhow::Result<Value> {
    let params = task.get("params").context("missing params")?;
    let git_url = params.get("git_url").and_then(|v| v.as_str()).context("missing git_url")?;
    let rev = params.get("rev").and_then(|v| v.as_str()).context("missing rev")?;
    let subdir = params.get("subdir").and_then(|v| v.as_str()).unwrap_or("");
    let use_cache = params.get("use_mathlib_cache").and_then(|v| v.as_bool()).unwrap_or(true);
    let artifacts_root = params.get("artifacts_root").and_then(|v| v.as_str()).unwrap_or(".lake/build/lib");
    let docker_image = params.get("docker_image").and_then(|v| v.as_str()).unwrap_or("leanprovercommunity/lean:latest");

    let require_artifact_hash = params.get("require_artifact_hash").and_then(|v| v.as_bool()).unwrap_or(true);

    let cmd_arr = params.get("cmd").and_then(|v| v.as_array()).cloned()
        .unwrap_or_else(|| vec![Value::String("lake".into()), Value::String("build".into())]);
    let cmd_vec: Vec<String> = cmd_arr.into_iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
    if cmd_vec.is_empty() { return Err(anyhow!("empty cmd")); }

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
        return Err(anyhow!("subdir does not exist: {}", workdir.display()));
    }

    // Build inside docker:
    // - capture all output to /workspace/.gmf_build.log
    // - compute build_log_sha256
    // - compute artifacts manifest + sha (if require_artifact_hash)
    // - write result_core JSON to /workspace/.gmf_result_core.json
    let bash = format!(r#"
set +e
cd /workspace/{subdir}
LOG="/workspace/.gmf_build.log"
RES="/workspace/.gmf_result_core.json"
ARTROOT="/workspace/{subdir}/{artifacts_root}"

( {"cache_cmd"} {cmd} ) >"$LOG" 2>&1
RC=$?

# build log hash
BLH=$(sha256sum "$LOG" | awk '{{print $1}}')

OK=false
if [ "$RC" -eq 0 ]; then OK=true; fi

ART_COUNT=0
ART_MANIFEST_SHA=""
if {require_hash}; then
  if [ -d "$ARTROOT" ]; then
    # manifest sorted by path, format: "<sha>  <relpath>"
    MAN="/workspace/.gmf_artifacts.manifest"
    (cd "$ARTROOT" && find . -type f -print0 | sort -z | xargs -0 sha256sum) > "$MAN"
    ART_COUNT=$(wc -l < "$MAN" | tr -d ' ')
    ART_MANIFEST_SHA=$(sha256sum "$MAN" | awk '{{print $1}}')
  else
    # required but missing => fail deterministic hash
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

    // run docker
    let (code, log) = run_cmd(
        Command::new("docker")
            .arg("run").arg("--rm")
            .arg("-v").arg(format!("{}:/workspace", repo.display()))
            .arg("-w").arg("/workspace")
            .arg(docker_image)
            .arg("bash").arg("-lc").arg(bash)
    )?;
    if code != 0 {
        // docker itself failed
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

    // read result_core from repo root
    let result_path = repo.join(".gmf_result_core.json");
    let txt = fs::read_to_string(&result_path).context("missing .gmf_result_core.json")?;
    let v: Value = serde_json::from_str(&txt).context("bad result_core json")?;
    Ok(v)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let seed_b64 = load_or_create_seed_b64()?;
    let pub_b64 = pubkey_b64_from_seed(&seed_b64)?;
    let device_id = device_id_from_pubkey_b64(&pub_b64)?;
    eprintln!("GMF worker device_id={device_id}");

    // consent token (device signed)
    let caps = serde_json::json!({
        "max_cpu_percent": args.max_cpu_percent,
        "wifi_only": args.wifi_only,
        "only_while_charging": args.only_while_charging
    });
    let mut consent = make_consent(&device_id, &caps);
    let payload = consent.get("consent_payload").unwrap().clone();
    let sig_b64 = sign_payload_b64(&seed_b64, &payload)?;
    consent.as_object_mut().unwrap().insert("device_sig_b64".into(), Value::String(sig_b64));
    let consent_token_json = serde_json::to_string(&consent)?;

    let client = reqwest::Client::new();

    loop {
        // pull
        let pull_payload = serde_json::json!({ "requested_at": chrono::Utc::now().to_rfc3339() });
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
            _ => { thread::sleep(Duration::from_secs(args.loop_seconds)); continue; }
        };

        let task = pull_json.get("task").cloned().unwrap_or(Value::Null);
        if task.is_null() {
            eprintln!("no task; sleep…");
            thread::sleep(Duration::from_secs(args.loop_seconds));
            continue;
        }

        let task_id = task.get("task_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let kind = task.get("kind").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();

        let result_core = match kind.as_str() {
            "lean_check" => {
                eprintln!("solve lean_check {task_id} …");
                solve_lean_check(&task).unwrap_or_else(|e| serde_json::json!({
                    "ok": false,
                    "exit_code": 1,
                    "build_log_sha256": hex::encode(sha256(e.to_string().as_bytes())),
                    "artifacts_root": ".lake/build/lib",
                    "artifacts_count": 0,
                    "artifacts_manifest_sha256": "",
                    "docker_image": "unknown"
                }))
            }
            _ => {
                eprintln!("unknown kind={kind}; skipping");
                thread::sleep(Duration::from_secs(args.loop_seconds));
                continue;
            }
        };

        // submit (result_core is now rich + hash-based)
        let submit_payload = serde_json::json!({
            "task_id": task_id,
            "result_core": result_core,
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
                let fraud = ssr.pointer("/receipt_payload/fraud_flag").and_then(|x| x.as_bool()).unwrap_or(false);
                eprintln!("SSR ok: delta={delta} fraud={fraud}");
            }
            Ok(r) => {
                let t = r.text().await.unwrap_or_default();
                eprintln!("submit: {} {}", r.status(), t);
            }
            Err(e) => eprintln!("submit error: {e}"),
        }

        thread::sleep(Duration::from_secs(args.loop_seconds));
    }
}
