use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use serde_json::Value;
use sha2::{Digest, Sha256};


const MAX_LEDGER_BYTES: usize = 25 * 1024 * 1024; // 25MB hard cap for mobile/helper
const HTTP_TIMEOUT_SECS: u64 = 30;

async fn fetch_limited(url: &str) -> Result<Vec<u8>> {
    use std::time::Duration;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()?;
    let resp = client.get(url).send().await?;
    if let Some(len) = resp.content_length() {
        if len as usize > MAX_LEDGER_BYTES {
            return Err(anyhow!("ledger too large: {} bytes", len));
        }
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > MAX_LEDGER_BYTES {
        return Err(anyhow!("ledger too large after download: {} bytes", bytes.len()));
    }
    Ok(bytes.to_vec())
}


use reqwest::header::HeaderMap;
use tokio::time::{timeout, Duration};

const PAGE_MAX_LINES: usize = 5000; // must be <= relay cap
const PAGE_TIMEOUT_SECS: u64 = 30;

async fn fetch_ledger_chunk(relay_base: &str, endpoint: &str, offset_lines: usize, max_lines: usize) -> Result<(Vec<u8>, bool, usize)> {
    // returns: (raw_bytes, eof, next_offset)
    let url_endpoint = params.get("ledger_endpoint").and_then(|v| v.as_str())
        .unwrap_or(&format!("/v1/ledger/ssr/{date}"));

    // stream paging: hash digest equals sha256(full_file_bytes)
    let mut hasher = Sha256::new();
    let mut offset: usize = 0;
    let mut eof = false;

    let mut total = 0i64;
    let mut valid = 0i64;
    let mut invalid = 0i64;
    let mut parse_err = 0i64;
    let mut policy_ids = std::collections::HashSet::<String>::new();

    while !eof {
        let (chunk, chunk_eof, next_offset) = fetch_ledger_chunk(relay_base, url_endpoint, offset, PAGE_MAX_LINES).await?;
        hasher.update(&chunk);

        let text = String::from_utf8_lossy(&chunk);
        for ln in text.lines() {
            let t = ln.trim();
            if t.is_empty() { continue; }
            total += 1;
            match serde_json::from_str::<Value>(t) {
                Ok(v) => {
                    if let Some(pid) = v.get("receipt_payload").and_then(|p| p.get("policy_id")).and_then(|x| x.as_str()) {
                        policy_ids.insert(pid.to_string());
                    }
                    match verify_ssr_line(t) {
                        Ok(true) => valid += 1,
                        Ok(false) => invalid += 1,
                        Err(_) => { invalid += 1; }
                    }
                }
                Err(_) => { parse_err += 1; }
            }
        }

        eof = chunk_eof;
        offset = next_offset;
        if chunk.is_empty() { break; }
    }

    let digest = hex::encode(hasher.finalize());
    // (paging loop handles counting)

    for ln in [].iter() {
        let t = ln.trim();
        if t.is_empty() { continue; }
        total += 1;
        match serde_json::from_str::<Value>(t) {
            Ok(v) => {
                if let Some(pid) = v.get("receipt_payload").and_then(|p| p.get("policy_id")).and_then(|x| x.as_str()) {
                    policy_ids.insert(pid.to_string());
                }
                match verify_ssr_line(t) {
                    Ok(true) => valid += 1,
                    Ok(false) => invalid += 1,
                    Err(_) => { invalid += 1; }
                }
            }
            Err(_) => { parse_err += 1; }
        }
    }

    let mut pids: Vec<String> = policy_ids.into_iter().collect();
    pids.sort();

    Ok(serde_json::json!({
        "ok": invalid == 0 && parse_err == 0,
        "exit_code": if invalid == 0 && parse_err == 0 { 0 } else { 2 },
        "date": date,
        "ssr_total": total,
        "ssr_valid_sig": valid,
        "ssr_invalid_sig": invalid,
        "ssr_parse_errors": parse_err,
        "policy_ids": pids,
        "ledger_digest_sha256": digest,
        "relay_base_url": relay_base
    }))
}

pub async fn run_ledger_audit(relay_base: &str, params: &Value) -> Result<Value> {
    let date = params.get("date").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("missing params.date"))?;
    let top_n = params.get("top_n").and_then(|v| v.as_i64()).unwrap_or(1000).max(1) as usize;
    let endpoint = params.get("ledger_endpoint").and_then(|v| v.as_str())
        .unwrap_or(&format!("/v1/ledger/ssr/{date}"));
    let url_endpoint = params.get("ledger_endpoint").and_then(|v| v.as_str())
        .unwrap_or(&format!("/v1/ledger/ssr/{date}"));

    let mut total = 0i64;
    let mut credits: std::collections::HashMap<String, i64> = std::collections::HashMap::new();

    let mut offset: usize = 0;
    let mut eof = false;

    while !eof {
        let (chunk, chunk_eof, next_offset) = fetch_ledger_chunk(relay_base, url_endpoint, offset, PAGE_MAX_LINES).await?;
        let text = String::from_utf8_lossy(&chunk);

        for ln in text.lines() {
            let t = ln.trim();
            if t.is_empty() { continue; }
            total += 1;
            let ssr: Value = match serde_json::from_str(t) { Ok(v) => v, Err(_) => continue };
            let payload = match ssr.get("receipt_payload") { Some(p) => p, None => continue };
            let dev = match payload.get("device_id").and_then(|v| v.as_str()) { Some(x) => x, None => continue };
            let delta = payload.get("credits_delta_micro").and_then(|v| v.as_i64()).unwrap_or(0);
            *credits.entry(dev.to_string()).or_insert(0) += delta;
        }

        eof = chunk_eof;
        offset = next_offset;
        if chunk.is_empty() { break; }
    }
    let mut credits: std::collections::HashMap<String, i64> = std::collections::HashMap::new();

    for ln in text.lines() {
        let t = ln.trim();
        if t.is_empty() { continue; }
        total += 1;
        let ssr: Value = match serde_json::from_str(t) { Ok(v) => v, Err(_) => continue };
        let payload = match ssr.get("receipt_payload") { Some(p) => p, None => continue };
        let dev = match payload.get("device_id").and_then(|v| v.as_str()) { Some(x) => x, None => continue };
        let delta = payload.get("credits_delta_micro").and_then(|v| v.as_i64()).unwrap_or(0);
        *credits.entry(dev.to_string()).or_insert(0) += delta;
    }

    let credits_devices = credits.len() as i64;
    let credits_total_micro: i64 = credits.values().sum();

    // canonical credits export
    let export = serde_json::json!({
        "date": date,
        "credits_micro_by_device_id": credits
    });
    let export_bytes = jcs_canonicalize(&export);
    let export_digest = sha256_hex(&export_bytes);

    // leaderboard top N
    let mut rows: Vec<(String,i64)> = export["credits_micro_by_device_id"]
        .as_object().unwrap()
        .iter()
        .map(|(k,v)| (k.clone(), v.as_i64().unwrap_or(0)))
        .collect();
    rows.sort_by(|a,b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(top_n);

    let entries: Vec<Value> = rows.iter().map(|(d,c)| serde_json::json!({"device_id": d, "credits_micro": c})).collect();
    let leaderboard = serde_json::json!({"date": date, "entries": entries});
    let lb_bytes = jcs_canonicalize(&leaderboard);
    let lb_digest = sha256_hex(&lb_bytes);

    Ok(serde_json::json!({
        "ok": true,
        "exit_code": 0,
        "date": date,
        "ssr_total": total,
        "credits_devices": credits_devices,
        "credits_total_micro": credits_total_micro,
        "leaderboard_top_n": top_n as i64,
        "leaderboard_digest_sha256": lb_digest,
        "credits_export_digest_sha256": export_digest,
        "relay_base_url": relay_base
    }))
}
