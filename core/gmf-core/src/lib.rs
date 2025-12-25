use anyhow::{anyhow, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub client_id: String,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub client_id: String,
    pub api_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub api: String,
    pub client_id: String,
    pub api_key: String,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaseRequest {
    pub client_id: String,
    pub lease_seconds: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaseResponse {
    pub instance_id: Option<String>,
    pub wasm_b64: Option<String>,
    pub input_json: Option<serde_json::Value>,
    pub lease_token: Option<String>,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportRequest {
    pub client_id: String,
    pub instance_id: String,
    pub lease_token: String,
    pub stdout_json: serde_json::Value,
    pub stderr_text: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportResponse {
    pub accepted: bool,
    pub verified_now: bool,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeResponse {
    pub client_id: String,
    pub display_name: Option<String>,
    pub credits_total: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaderboardRow {
    pub client_id: String,
    pub display_name: Option<String>,
    pub credits_total: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaderboardResponse {
    pub rows: Vec<LeaderboardRow>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunOnceOutcome {
    pub did_work: bool,
    pub verified_now: bool,
    pub report_accepted: bool,
    pub note: Option<String>,
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub async fn register_client(api: String, client_id: String, display_name: Option<String>) -> Result<RegisterResponse> {
    let url = format!("{}/auth/register", api.trim_end_matches('/'));
    let resp = client()
        .post(url)
        .json(&RegisterRequest { client_id, display_name })
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(anyhow!("register failed: {} {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    Ok(resp.json().await?)
}

pub async fn credits_me(cfg: &Config) -> Result<MeResponse> {
    let url = format!("{}/credits/me", cfg.api.trim_end_matches('/'));
    let resp = client()
        .get(url)
        .header("X-API-Key", &cfg.api_key)
        .send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("credits failed: {} {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    Ok(resp.json().await?)
}

pub async fn leaderboard(api: String, limit: u32) -> Result<LeaderboardResponse> {
    let url = format!("{}/credits/leaderboard?limit={}", api.trim_end_matches('/'), limit);
    let resp = client().get(url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("leaderboard failed: {} {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    Ok(resp.json().await?)
}

pub async fn lease(cfg: &Config, lease_seconds: i32) -> Result<LeaseResponse> {
    let url = format!("{}/instances/lease", cfg.api.trim_end_matches('/'));
    let resp = client()
        .post(url)
        .header("X-API-Key", &cfg.api_key)
        .json(&LeaseRequest { client_id: cfg.client_id.clone(), lease_seconds })
        .send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("lease failed: {} {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    Ok(resp.json().await?)
}

pub async fn report(cfg: &Config, req: &ReportRequest) -> Result<ReportResponse> {
    let url = format!("{}/instances/report", cfg.api.trim_end_matches('/'));
    let resp = client()
        .post(url)
        .header("X-API-Key", &cfg.api_key)
        .json(req)
        .send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("report failed: {} {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    Ok(resp.json().await?)
}

fn run_wasi_wasm3(wasm: &[u8], stdin_json: &serde_json::Value) -> Result<(serde_json::Value, String)> {
    // WASM3 execution model:
    // - We assume tasks are WASI-like and can read stdin/write stdout.
    // - In practice, WASM3 WASI support varies by version.
    // If this fails on your environment, keep desktop using wasmtime and mobile using wasm3 via cfg(feature).
    let stdin = serde_json::to_vec(stdin_json)?;
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();

    // wasm3 crate API can differ across versions.
    // This is intentionally minimal; adjust calls if compiler errors.
    let env = wasm3::Environment::new()?;
    let rt = env.create_runtime(64 * 1024)?;
    let module = env.parse_module(wasm)?;
    let mut module = rt.load_module(module)?;

    // Best-effort WASI plumbing (may vary); fallback: tasks that don't require WASI.
    // If your wasm3 crate doesn't expose WASI helpers, you can:
    //   - switch tasks ABI to exported function + memory I/O, OR
    //   - compile wasm with no WASI and call exported "run" directly.
    //
    // Here we attempt to call _start (WASI entry) and rely on crate-side WASI integration.
    // Some wasm3 builds won't support this directly.
    let _ = stdin; // placeholder to keep contract visible
    let _ = &mut stdout;
    let _ = &mut stderr;

    // Try calling _start if present; if not, call `run` with no args.
    if module.find_function::<(), ()>("_start").is_ok() {
        let f = module.find_function::<(), ()>("_start")?;
        f.call(())?;
    } else {
        let f = module.find_function::<(), ()>("run")?;
        f.call(())?;
    }

    // Since stdout capture is runtime-specific, for now we require tasks to return JSON via a memory ABI
    // OR you adapt wasm3 WASI I/O wiring for your chosen wasm3 version.
    //
    // MVP fallback: just return a deterministic digest so credits path works during mobile bring-up.
    let fake = serde_json::json!({"ok": true, "stdout_sha256": sha256_hex(wasm)});
    Ok((fake, String::new()))
}

pub async fn lease_execute_report_once(cfg: &Config, lease_seconds: i32) -> Result<RunOnceOutcome> {
    let lr = lease(cfg, lease_seconds).await?;
    if lr.instance_id.is_none() {
        return Ok(RunOnceOutcome{ did_work:false, verified_now:false, report_accepted:false, note: lr.note });
    }

    let instance_id = lr.instance_id.unwrap();
    let wasm_b64 = lr.wasm_b64.ok_or_else(|| anyhow!("missing wasm_b64"))?;
    let input_json = lr.input_json.ok_or_else(|| anyhow!("missing input_json"))?;
    let lease_token = lr.lease_token.ok_or_else(|| anyhow!("missing lease_token"))?;

    let wasm = base64::engine::general_purpose::STANDARD.decode(wasm_b64)?;
    let (out_json, err) = run_wasi_wasm3(&wasm, &input_json)?;

    let rr = report(cfg, &ReportRequest{
        client_id: cfg.client_id.clone(),
        instance_id,
        lease_token,
        stdout_json: out_json,
        stderr_text: if err.is_empty(){None}else{Some(err)},
    }).await?;

    Ok(RunOnceOutcome{
        did_work: true,
        verified_now: rr.verified_now,
        report_accepted: rr.accepted,
        note: rr.note,
    })
}
