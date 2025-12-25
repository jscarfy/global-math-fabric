use flutter_rust_bridge::frb;
use gmf_core::{Config, RegisterResponse, RunOnceOutcome, LeaderboardResponse, MeResponse};

#[frb(sync)]
pub fn version() -> String {
    "gmf_mobile_ffi_v0".to_string()
}

pub async fn register(api: String, client_id: String, display_name: Option<String>) -> anyhow::Result<RegisterResponse> {
    gmf_core::register_client(api, client_id, display_name).await.map_err(|e| anyhow::anyhow!(e.to_string()))
}

pub async fn credits_me(cfg: Config) -> anyhow::Result<MeResponse> {
    gmf_core::credits_me(&cfg).await.map_err(|e| anyhow::anyhow!(e.to_string()))
}

pub async fn leaderboard(api: String, limit: u32) -> anyhow::Result<LeaderboardResponse> {
    gmf_core::leaderboard(api, limit).await.map_err(|e| anyhow::anyhow!(e.to_string()))
}

pub async fn run_once(cfg: Config, lease_seconds: i32) -> anyhow::Result<RunOnceOutcome> {
    gmf_core::lease_execute_report_once(&cfg, lease_seconds).await.map_err(|e| anyhow::anyhow!(e.to_string()))
}
