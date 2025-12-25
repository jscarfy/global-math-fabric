mod helper_tasks;
use anyhow::{Context, anyhow};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer};
use rand::rngs::OsRng;
use serde_json::Value;
use std::{fs, path::{Path, PathBuf}, thread, time::Duration, process::Command};

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

fn sha256_file_hex(p: &Path) -> anyhow::Result<String> {
    if !p.exists() { return Ok("".into()); }
    let bytes = fs::read(p)?;
    Ok(hex::encode(sha256(&bytes)))
}

fn git_rev_parse(repo: &Path, spec: &str) -> anyhow::Result<String> {
    let (code, out) = run_cmd(Command::new("git").args(["rev-parse", spec]).current_dir(repo))?;
    if code != 0 {
        return Err(anyhow!("git rev-parse failed ({spec}): {out}"));
    }
    Ok(out.trim().to_string())
}

/// Docker script writes /workspace/.gmf_result_core.json (partial: build+artifacts)
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
    let txt = fs::read_to_string(&result_path).context("missing .gmf_result_core.json")?;
    let v: Value = serde_json::from_str(&txt).context("bad .gmf_result_core.json")?;
    Ok(v)
}

fn solve_lean_check(task: &Value) -> anyhow::Result<Value> {
    let params = task.get("params").context("missing params")?;
    let git_url = params.get("git_url").and_then(|v| v.as_str()).context("missing git_url")?;
    let rev = params.get("rev").and_then(|v| v.as_str()).context("missing rev")?;
    let subdir = params.get("subdir").and_then(|v| v.as_str()).unwrap_or("");
    let use_cache = params.get("use_mathlib_cache").and_then(|v| v.as_bool()).unwrap_or(true);
    let artifacts_root = params.get("artifacts_root").and_then(|v| v.as_str()).unwrap_or(".lake/build/lib");

    let docker_image = params.get("docker_image").and_then(|v| v.as_str()).unwrap_or("leanprovercommunity/lean:latest");
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

    // HOST-computed source pinning
    let (git_rev, git_tree, lean_toolchain_sha256, lakefile_sha256, lake_manifest_sha256) = if require_source_hash {
        let git_rev = git_rev_parse(&repo, "HEAD")?;
        let git_tree = git_rev_parse(&repo, "HEAD^{tree}")?;

        // hash key files relative to workdir
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

    // Docker does build + artifacts hashing (partial result_core)
    let mut partial = docker_build_and_hash(&repo, subdir, artifacts_root, docker_image, use_cache, &cmd_vec, require_artifact_hash)?;

    // merge source pinning into result_core
    if require_source_hash {
        partial.as_object_mut().unwrap().insert("git_rev".into(), Value::String(git_rev));
        partial.as_object_mut().unwrap().insert("git_tree".into(), Value::String(git_tree));
        partial.as_object_mut().unwrap().insert("lean_toolchain_sha256".into(), Value::String(lean_toolchain_sha256));
        partial.as_object_mut().unwrap().insert("lakefile_sha256".into(), Value::String(lakefile_sha256));
        partial.as_object_mut().unwrap().insert("lake_manifest_sha256".into(), Value::String(lake_manifest_sha256));
    } else {
        partial.as_object_mut().unwrap().insert("git_rev".into(), Value::String("".into()));
        partial.as_object_mut().unwrap().insert("git_tree".into(), Value::String("".into()));
        partial.as_object_mut().unwrap().insert("lean_toolchain_sha256".into(), Value::String("".into()));
        partial.as_object_mut().unwrap().insert("lakefile_sha256".into(), Value::String("".into()));
        partial.as_object_mut().unwrap().insert("lake_manifest_sha256".into(), Value::String("".into()));
    }

    Ok(partial)
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
            
            "receipt_verify" => {
                // Mobile helper: verify SSR signatures + digest the day ledger
                let rc = crate::helper_tasks::run_receipt_verify(&relay_base_url, &task.params).await?;
                rc
            }
            "ledger_audit" => {
                // Mobile helper: aggregate credits + leaderboard digest for the day
                let rc = crate::helper_tasks::run_ledger_audit(&relay_base_url, &task.params).await?;
                rc
            }

            
            "audit_final_verify" => {
                let rc = crate::helper_tasks::run_audit_final_verify(&relay_base_url, &task.params).await?;
                rc
            }

            "report_verify" => {
                let rc = crate::helper_tasks::run_report_verify(&relay_base_url, &task.params).await?;

                // report_audit receipt (best-effort) if ok
                let ok2 = rc.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                if ok2 {
                    let rk = rc.get("report_kind").and_then(|v| v.as_str()).unwrap_or("");
                    let pid = rc.get("period_id").and_then(|v| v.as_str()).unwrap_or("");
                    let roll = rc.get("rollup_sha256").and_then(|v| v.as_str()).unwrap_or("");
                    let payload2 = serde_json::json!({
                        "report_kind": rk,
                        "period_id": pid,
                        "target_rollup_sha256": roll,
                        "verifier_result_ok": true,
                        "verifier_detail": rc
                    });
                    let body2 = serde_json::json!({
                        "consent_token_json": consent_token_json,
                        "device_pubkey_b64": device_pubkey_b64,
                        "report_audit_payload": payload2
                    });
                    let url2 = format!("{}/v1/report_audit/receipt", relay_base_url.trim_end_matches('/'));
                    let _ = reqwest::Client::new().post(&url2).json(&body2).send().await;
                }


                // meta-attest (best-effort) if ok
                let do_meta = task.params.get("meta_attest").and_then(|v| v.as_bool()).unwrap_or(true);
                if do_meta {
                    let ok = rc.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                    if ok {
                        let rk = rc.get("report_kind").and_then(|v| v.as_str()).unwrap_or("");
                        let target_kind = if rk == "monthly" { "monthly_final" } else { "yearly_final" };
                        let anchor_sha = rc.get("rollup_sha256").and_then(|v| v.as_str()).unwrap_or("");

                        let payload = serde_json::json!({
                            "date": task.params.get("period_id").and_then(|v| v.as_str()).unwrap_or(""),
                            "target_kind": target_kind,
                            "target_anchor_sha256": anchor_sha,
                            "verifier_result_ok": true,
                            "verifier_detail": rc
                        });
                        let body = serde_json::json!({
                            "consent_token_json": consent_token_json,
                            "device_pubkey_b64": device_pubkey_b64,
                            "meta_audit_payload": payload
                        });
                        let url = format!("{}/v1/meta_audit/attest", relay_base_url.trim_end_matches('/'));
                        let _ = reqwest::Client::new().post(&url).json(&body).send().await;
                    }
                }

                rc
            }

            "canonical_export_verify" => {
                let rc = crate::helper_tasks::run_canonical_export_verify(&relay_base_url, &task.params).await?;

                // meta-attest canonical_export (best-effort) if ok
                let do_meta = task.params.get("meta_attest").and_then(|v| v.as_bool()).unwrap_or(true);
                if do_meta {
                    let ok = rc.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                    if ok {
                        let rk = rc.get("report_kind").and_then(|v| v.as_str()).unwrap_or("");
                        let pid = rc.get("period_id").and_then(|v| v.as_str()).unwrap_or("");
                        let anchor_sha = rc.get("export_rollup_sha256").and_then(|v| v.as_str()).unwrap_or("");

                        let payload = serde_json::json!({
                            "date": pid,                       // period_id as date key
                            "target_kind": "canonical_export",
                            "target_anchor_sha256": anchor_sha,
                            "report_kind": rk,
                            "period_id": pid,
                            "verifier_result_ok": true,
                            "verifier_detail": rc
                        });
                        let body = serde_json::json!({
                            "consent_token_json": consent_token_json,
                            "device_pubkey_b64": device_pubkey_b64,
                            "meta_audit_payload": payload
                        });
                        let url = format!("{}/v1/meta_audit/attest", relay_base_url.trim_end_matches('/'));
                        let _ = reqwest::Client::new().post(&url).json(&body).send().await;
                    }
                }

                rc
            }
"final_verify" => {
                let rc = crate::helper_tasks::run_final_verify(&relay_base_url, &task.params).await?;

                // Auto-attest (default true) — writes a server-signed audit receipt
                let do_attest = task.params.get("attest").and_then(|v| v.as_bool()).unwrap_or(true);
                if do_attest {
                    if let (Some(date), Some(final_sig_ok), Some(final_sha)) = (
                        rc.get("date").and_then(|v| v.as_str()),
                        rc.get("final_sig_ok").and_then(|v| v.as_bool()),
                        rc.get("inbox_sha_matches_final").or_else(|| Some(&serde_json::Value::Null)).cloned(),
                    ) {
                        // Build minimal attest_payload; relay enforces final existence + sha match + final_sig_ok==true
                        let attest_payload = serde_json::json!({
                            "date": date,
                            "final_sig_ok": final_sig_ok,
                            "final_ssr_sha256": rc.get("final_ssr_sha256").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            "verifier_kind": "gmf_worker_helper",
                            "verifier_version": env!("CARGO_PKG_VERSION")
                        });

                        let body = serde_json::json!({
                            "consent_token_json": consent_token_json,
                            "device_pubkey_b64": device_pubkey_b64,
                            "attest_payload": attest_payload
                        });

                        let url = format!("{}/v1/audit/attest", relay_base_url.trim_end_matches('/'));
                        let _ = reqwest::Client::new().post(&url).json(&body).send().await;
                    }
                }

                rc
            }
"lean_check" => {
                eprintln!("solve lean_check {task_id} …");
                solve_lean_check(&task).unwrap_or_else(|e| serde_json::json!({
                    "ok": false,
                    "exit_code": 1,
                    "build_log_sha256": hex::encode(sha256(e.to_string().as_bytes())),
                    "artifacts_root": ".lake/build/lib",
                    "artifacts_count": 0,
                    "artifacts_manifest_sha256": "",
                    "docker_image": "unknown",
                    "git_rev": "",
                    "git_tree": "",
                    "lean_toolchain_sha256": "",
                    "lakefile_sha256": "",
                    "lake_manifest_sha256": ""
                }))
            }
            _ => {
                eprintln!("unknown kind={kind}; skipping");
                thread::sleep(Duration::from_secs(args.loop_seconds));
                continue;
            }
        };

        // submit
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
