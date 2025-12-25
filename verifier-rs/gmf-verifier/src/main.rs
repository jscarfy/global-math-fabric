use anyhow::{anyhow, Result};
use base64::Engine;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct ReplayQueueResponse {
    item: Option<ReplayItem>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct ReplayItem {
    instance_id: String,
    manifest: serde_json::Value,
    wasm_b64: String,
    input_json: serde_json::Value,
    winning_sha256: String,
}

#[derive(Debug, serde::Serialize)]
struct ReplayReportRequest {
    instance_id: String,
    verifier_id: String,
    ok: bool,
    detail: serde_json::Value,
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

#[tokio::main]
async fn main() -> Result<()> {
    let api = std::env::var("GMF_API").unwrap_or_else(|_| "http://api:8000".to_string());
    let verifier_id = std::env::var("GMF_VERIFIER_ID").unwrap_or_else(|_| "verifier-1".to_string());
    let key = std::env::var("GMF_VERIFIER_SHARED_KEY").unwrap_or_else(|_| "dev-verifier-key".to_string());

    loop {
        let qurl = format!("{}/replay/queue", api.trim_end_matches('/'));
        let resp = client()
            .get(&qurl)
            .header("X-Verifier-Key", &key)
            .header("X-Verifier-Id", &verifier_id)
            .send()
            .await?;

        if !resp.status().is_success() {
            eprintln!("queue http {}: {}", resp.status(), resp.text().await.unwrap_or_default());
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        let q: ReplayQueueResponse = resp.json().await?;
        let Some(item) = q.item else {
            tokio::time::sleep(Duration::from_secs(10)).await;
            continue;
        };

        // Only execute mobile ABI1 tasks
        let abi = item.manifest.get("abi").and_then(|v| v.as_str()).unwrap_or("");
        if abi != "gmf-abi-1" {
            // refuse non-abi1 tasks
            let rep = ReplayReportRequest{
                instance_id: item.instance_id,
                verifier_id: verifier_id.clone(),
                ok: false,
                detail: serde_json::json!({"reason":"non_abi1_task","abi":abi}),
            };
            post_report(&api, &key, rep).await?;
            continue;
        }

        let wasm = base64::engine::general_purpose::STANDARD.decode(item.wasm_b64)?;
        let out = gmf_core::run_abi1_bytes(&wasm, &item.input_json);

        let (ok, detail) = match out {
            Ok(v) => {
                let h = gmf_core::canonical_stdout_sha256(&v);
                let ok = h == item.winning_sha256;
                (ok, serde_json::json!({"computed_sha256": h, "winning_sha256": item.winning_sha256}))
            }
            Err(e) => (false, serde_json::json!({"error": e.to_string()})),
        };

        let rep = ReplayReportRequest{
            instance_id: item.instance_id,
            verifier_id: verifier_id.clone(),
            ok,
            detail,
        };
        post_report(&api, &key, rep).await?;

        // small pacing to avoid hammering DB
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn post_report(api: &str, key: &str, rep: ReplayReportRequest) -> Result<()> {
    let url = format!("{}/replay/report", api.trim_end_matches('/'));
    let resp = client()
        .post(&url)
        .header("X-Verifier-Key", key)
            .header("X-Verifier-Id", &rep.verifier_id)
        .json(&rep)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("report http {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    Ok(())
}
