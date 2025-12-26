mod policy;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, time::Duration};

#[derive(Parser, Debug)]
#[command(name="gmf_agent")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// create local config dir + keypair
    Init {
        #[arg(long, default_value="http://127.0.0.1:8787")]
        relay: String,
        #[arg(long, default_value="my-device")]
        device_name: String,
    },
    /// enroll (opt-in) with relay: obtain server-signed consent token
    Enroll,
    /// run forever: poll tasks + execute via gmf_worker (helper-capable or full)
    Run {
        #[arg(long, default_value_t=5)]
        loop_seconds: u64,
    },
    /// show config status
    Status,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AgentConfig {
    policy: policy::RunPolicy,

    relay: String,
    device_name: String,
    device_id: String,
    device_pubkey_b64: String,
    device_seckey_b64: String,
    consent_token_json: Option<serde_json::Value>,
}

fn cfg_dir() -> Result<PathBuf> {
    let d = dirs::home_dir().ok_or_else(|| anyhow!("no home dir"))?
        .join(".gmf_agent");
    Ok(d)
}
fn cfg_path() -> Result<PathBuf> { Ok(cfg_dir()?.join("config.json")) }

fn b64(b: &[u8]) -> String { base64::engine::general_purpose::STANDARD.encode(b) }
fn b64d(s: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

fn save_cfg(cfg: &AgentConfig) -> Result<()> {
    fs::create_dir_all(cfg_dir()?)?;
    fs::write(cfg_path()?, serde_json::to_vec_pretty(cfg)?)?;
    Ok(())
}
fn load_cfg() -> Result<AgentConfig> {
    let p = cfg_path()?;
    let txt = fs::read_to_string(&p)
        .map_err(|_| anyhow!("missing config: run `gmf_agent init` first: {}", p.display()))?;
    Ok(serde_json::from_str(&txt)?)
}

fn random_device_id() -> String {
    use rand::RngCore;
    let mut r = [0u8; 16];
    OsRng.fill_bytes(&mut r);
    hex::encode(r)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    match args.cmd {
        Cmd::Init { relay, device_name } => {
            let mut csprng = OsRng;
            let sk = SigningKey::generate(&mut csprng);
            let vk: VerifyingKey = sk.verifying_key();

            let cfg = AgentConfig{
                relay,
                device_name,
                device_id: random_device_id(),
                device_pubkey_b64: b64(vk.as_bytes()),
                device_seckey_b64: b64(sk.as_bytes()),
                consent_token_json: None,
                policy: policy::RunPolicy::default(),
            };
            save_cfg(&cfg)?;
            println!("OK: wrote {}", cfg_path()?.display());
            println!("Next: gmf_agent enroll");
        }

        Cmd::Enroll => {
            let mut cfg = load_cfg()?;
            let url = format!("{}/v1/consent/register", cfg.relay.trim_end_matches('/'));
            let body = serde_json::json!({
                "device_id": cfg.device_id,
                "device_name": cfg.device_name,
                "device_pubkey_b64": cfg.device_pubkey_b64
            });

            let client = reqwest::Client::new();
            let resp = client.post(&url).json(&body).send().await?;
            if !resp.status().is_success() {
                return Err(anyhow!("enroll failed: {}", resp.status()));
            }
            let token: serde_json::Value = resp.json().await?;
            cfg.consent_token_json = Some(token);
            save_cfg(&cfg)?;
            println!("OK: enrolled; consent token saved.");
        }

        Cmd::Status => {
            let cfg = load_cfg()?;
            println!("{}", serde_json::to_string_pretty(&cfg)?);
        }

        Cmd::Run { loop_seconds } => {
            let cfg = load_cfg()?;
            let token = cfg.consent_token_json.clone().ok_or_else(|| anyhow!("not enrolled: run gmf_agent enroll"))?;

            // Delegate to existing gmf_worker binary for now (simple+robust)
            // You can later link worker as a library; this is the minimal “friend can run” path.
            let loop_s = loop_seconds.max(cfg.policy.min_loop_seconds);
            println!("Running agent loop against relay={} every {}s", cfg.relay, loop_s);

            loop {
                let cfg2 = load_cfg()?;
                if !policy::policy_allows_run(&cfg2.policy) {
                    eprintln!("[agent] policy pause (paused/quiet-hours/power/battery). sleeping {}s", loop_seconds);
                    tokio::time::sleep(Duration::from_secs(loop_seconds.max(cfg2.policy.min_loop_seconds))).await;
                    continue;
                }

                // Call gmf_worker in helper mode by env + args (assumes built)
                // On friends' machines: ship prebuilt gmf_worker + gmf_agent; or build from source.
                let st = std::process::Command::new("native/target/release/gmf_worker")
                    .env("GMF_CAPABILITIES", "helper")
                    .arg("--relay").arg(&cfg.relay)
                    .arg("--loop-seconds").arg(loop_s.to_string())
                    .status();

                match st {
                    Ok(s) => {
                        eprintln!("[agent] worker exited: {}; restarting in 5s", s);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    Err(e) => return Err(anyhow!("failed to start gmf_worker: {e}")),
                }
            }
        }
    }
    Ok(())
}
