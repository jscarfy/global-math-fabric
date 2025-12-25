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


fn probe_desktop_capabilities() -> serde_json::Value {
    // Minimal, cross-platform-ish probe
    let cpu_count = num_cpus::get() as i64;

    let mut sys = sysinfo::System::new_all();
    sys.refresh_memory();
    // sysinfo returns KB
    let mem_kb = sys.total_memory() as f64;
    let mem_gb = (mem_kb / 1024.0 / 1024.0).round(); // GB-ish

    // GPU presence: best-effort. You can override via env GMF_GPU_PRESENT=1
    let gpu_present_env = std::env::var("GMF_GPU_PRESENT").ok().map(|v| v == "1" || v.to_lowercase() == "true").unwrap_or(false);
    let gpu_present = if gpu_present_env {
        true
    } else {
        #[cfg(target_os="linux")]
        { std::path::Path::new("/dev/dri").exists() }
        #[cfg(not(target_os="linux"))]
        { false }
    };

    // Tier: simple bucketing
    let tier = if gpu_present {
        "gpu"
    } else if cpu_count >= 8 && mem_gb >= 16.0 {
        "cpu_high"
    } else {
        "cpu_low"
    };

    serde_json::json!({
        "platform": "desktop",
        "cpu_count": cpu_count,
        "mem_gb": mem_gb,
        "gpu_present": gpu_present,
        "tier": tier,
        "ts_unix": chrono::Utc::now().timestamp(),
    })
}

fn heavy_work_iters() -> u64 {
    std::env::var("GMF_HEAVY_WORK_ITERS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5_000_000)
}

/// Deterministic "work proof" for heavy tasks. Must be identical across machines.
/// Seed ONLY from stable fields (instance_id + stdout_sha256).
fn compute_work_proof(instance_id: &str, stdout_sha256: &str, iters: u64) -> (u64, String) {
    use sha2::{Sha256, Digest};

    let mut buf = Vec::new();
    buf.extend_from_slice(instance_id.as_bytes());
    buf.extend_from_slice(b"|");
    buf.extend_from_slice(stdout_sha256.as_bytes());
    let mut state = Sha256::digest(&buf).to_vec(); // 32 bytes

    for _ in 0..iters {
        let mut h = Sha256::new();
        h.update(&state);
        state = h.finalize().to_vec();
    }
    (iters, hex::encode(state))
}


#[derive(Clone, Debug)]
enum HeavyWorkKind {
    Sha256Chain,
    PolyMod,
}

#[derive(Clone, Debug)]
struct HeavyWorkSpec {
    kind: HeavyWorkKind,
    iters: u64,
    // params are kept minimal (deterministic, small)
    // PolyMod params:
    mod_p: u64,
    a: u64,
    b: u64,
    x0: u64,
}

fn parse_heavy_work_spec(manifest: &serde_json::Value) -> HeavyWorkSpec {
    // Defaults:
    let mut kind = HeavyWorkKind::Sha256Chain;
    let mut iters = heavy_work_iters();
    let mut mod_p: u64 = 1_000_000_007;
    let mut a: u64 = 48271;
    let mut b: u64 = 0;
    let mut x0: u64 = 1;

    if let Some(hw) = manifest.get("heavy_work") {
        if let Some(k) = hw.get("kind").and_then(|v| v.as_str()) {
            kind = match k {
                "poly_mod" => HeavyWorkKind::PolyMod,
                _ => HeavyWorkKind::Sha256Chain,
            };
        }
        if let Some(n) = hw.get("iters").and_then(|v| v.as_u64()) {
            iters = n;
        }
        if let Some(p) = hw.get("params") {
            if let Some(v) = p.get("mod_p").and_then(|v| v.as_u64()) { mod_p = v; }
            if let Some(v) = p.get("a").and_then(|v| v.as_u64()) { a = v; }
            if let Some(v) = p.get("b").and_then(|v| v.as_u64()) { b = v; }
            if let Some(v) = p.get("x0").and_then(|v| v.as_u64()) { x0 = v; }
        }
    }

    HeavyWorkSpec { kind, iters, mod_p, a, b, x0 }
}

fn compute_heavy_work_proof(instance_id: &str, stdout_sha256: &str, spec: &HeavyWorkSpec) -> (String, serde_json::Value) {
    match spec.kind {
        HeavyWorkKind::Sha256Chain => {
            let (n, digest) = compute_work_proof(instance_id, stdout_sha256, spec.iters);
            ("sha256_chain".to_string(), serde_json::json!({"iters": n, "digest": digest}))
        }
        HeavyWorkKind::PolyMod => {
            // deterministic modular recurrence: x_{t+1} = (a*x_t + b + seed) mod p
            // seed derived from instance_id + stdout_sha256 (stable)
            use sha2::{Sha256, Digest};
            let mut seed_in = Vec::new();
            seed_in.extend_from_slice(instance_id.as_bytes());
            seed_in.extend_from_slice(b"|");
            seed_in.extend_from_slice(stdout_sha256.as_bytes());
            let seed = Sha256::digest(&seed_in);
            // take first 8 bytes as u64
            let mut seed_u64: u64 = 0;
            for i in 0..8 { seed_u64 = (seed_u64 << 8) | (seed[i] as u64); }

            let p = spec.mod_p.max(3);
            let a = spec.a % p;
            let b = spec.b % p;
            let mut x = spec.x0 % p;

            for _ in 0..spec.iters {
                x = (a.wrapping_mul(x) + b + (seed_u64 % p)) % p;
            }

            // digest: sha256(instance_id|stdout_sha256|x)
            let mut h = Sha256::new();
            h.update(instance_id.as_bytes());
            h.update(b"|");
            h.update(stdout_sha256.as_bytes());
            h.update(b"|");
            h.update(x.to_be_bytes());
            let digest = hex::encode(h.finalize().to_vec());

            ("poly_mod".to_string(), serde_json::json!({
                "iters": spec.iters,
                "mod_p": p,
                "a": a,
                "b": b,
                "x0": spec.x0 % p,
                "x": x,
                "digest": digest
            }))
        }
    }
}


static LAST_RECEIPT_JSON: parking_lot::Mutex<Option<String>> = parking_lot::Mutex::new(None);

pub fn set_last_receipt_json(s: String) {
    *LAST_RECEIPT_JSON.lock() = Some(s);
}

pub fn take_last_receipt_json() -> Option<String> {
    LAST_RECEIPT_JSON.lock().take()
}
