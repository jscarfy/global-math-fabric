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


use std::collections::{HashMap, HashSet};

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Default)]
struct HelperCursorEntry {
    last_ts_unix_ms: i64,
    // de-dup only for the CURRENT last_ts_unix_ms (same-millisecond duplicates)
    seen_hashes_at_last_ts: Vec<String>
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Default)]
struct HelperCursor {
    // key: "{relay_base}|{date}|{kind}"
    entries: HashMap<String, HelperCursorEntry>
}

fn default_cursor_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("GMF_HELPER_CURSOR_PATH") {
        return std::path::PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(home).join(".gmf").join("helper_cursor.json")
}

fn load_cursor() -> HelperCursor {
    let path = default_cursor_path();
    if let Ok(txt) = std::fs::read_to_string(&path) {
        if let Ok(v) = serde_json::from_str::<HelperCursor>(&txt) {
            return v;
        }
    }
    HelperCursor::default()
}

fn save_cursor(cur: &HelperCursor) -> Result<()> {
    let path = default_cursor_path();
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(cur)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

fn line_hash_hex(line: &str) -> String {
    let mut h = Sha256::new();
    h.update(line.as_bytes());
    hex::encode(h.finalize())
}

// Robust ts extractor (must match relay behavior)
fn extract_ts_unix_ms_from_ssr(v: &Value) -> i64 {
    let p = v.get("receipt_payload");
    if let Some(p) = p {
        for k in ["server_time_unix_ms","issued_at_unix_ms","time_unix_ms","ts_unix_ms","server_time_ms","issued_at_ms","ts_ms"] {
            if let Some(x) = p.get(k).and_then(|y| y.as_i64()) {
                return x;
            }
        }
    }
    v.get("server_time_unix_ms").and_then(|y| y.as_i64()).unwrap_or(0)
}

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


async fn fetch_snapshot_json(relay_base: &str, date: &str) -> Result<serde_json::Value> {
    let url = format!("{}/v1/ledger/snapshot/{}", relay_base.trim_end_matches('/'), date);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(PAGE_TIMEOUT_SECS))
        .build()?;
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("snapshot fetch failed: {}", resp.status()));
    }


async fn fetch_delta_once(relay_base: &str, date: &str, since_unix_ms: i64, max_lines: usize) -> Result<(String, i64, bool)> {
    // returns: (jsonl_text, last_ts_header, may_have_more)
    let url = format!(
        "{}/v1/ledger/ssr_delta/{}?since_unix_ms={}&max_lines={}",
        relay_base.trim_end_matches('/'),
        date,
        since_unix_ms,
        max_lines.min(50_000).max(1)
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(PAGE_TIMEOUT_SECS))
        .build()?;

    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("ssr_delta fetch failed: {}", resp.status()));
    }
    let headers = resp.headers().clone();
    let last_ts: i64 = headers
        .get("X-GMF-LAST-TS-UNIX-MS")
        .and_then(|v| v.to_str().ok())
        .and_then(|t| t.parse().ok())
        .unwrap_or(since_unix_ms);

    let may_have_more = headers
        .get("X-GMF-MAY-HAVE-MORE")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0") == "1";

    let txt = resp.text().await?;
    Ok((txt, last_ts, may_have_more))
}
    let txt = resp.text().await?;
    Ok(serde_json::from_str(&txt)?)
}
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
    let mut snapshot_match = None;
    let mut snapshot_sha256 = None;
    if let Ok(snap) = fetch_snapshot_json(relay_base, date).await {
        if let Some(h) = snap.get("ssr_sha256").and_then(|v| v.as_str()) {
            snapshot_sha256 = Some(h.to_string());
            snapshot_match = Some(h == digest);
        }
    }

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
        "snapshot_sha256": snapshot_sha256,
        "snapshot_match": snapshot_match,
        "relay_base_url": relay_base
    }))
}

pub async fn run_ledger_audit(relay_base: &str, params: &Value) -> Result<Value> {
    let date = params.get("date").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("missing params.date"))?;

    let mode_str = params.get("mode").and_then(|v| v.as_str()).unwrap_or("delta");
    let reset_cursor = params.get("reset_cursor").and_then(|v| v.as_bool()).unwrap_or(false);
    let cursor_key = format!("{}|{}|{}", relay_base, date, "ledger_audit");

    let top_n = params.get("top_n").and_then(|v| v.as_i64()).unwrap_or(1000).max(1) as usize;
    let endpoint = params.get("ledger_endpoint").and_then(|v| v.as_str())
        .unwrap_or(&format!("/v1/ledger/ssr/{date}"));
        if mode_str == "full" {
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

    
    } else {
        // DELTA MODE: aggregate credits from new SSR lines only
        let mut cur = load_cursor();
        if reset_cursor { cur.entries.remove(&cursor_key); }
        let ent = cur.entries.entry(cursor_key.clone()).or_insert_with(|| HelperCursorEntry{ last_ts_unix_ms: 0, seen_hashes_at_last_ts: vec![] });

        let mut seen: HashSet<String> = ent.seen_hashes_at_last_ts.iter().cloned().collect();
        let mut since = ent.last_ts_unix_ms;
        let max_lines = params.get("max_lines").and_then(|v| v.as_i64()).unwrap_or(3000).clamp(1, 50000) as usize;

        let mut delta_total = 0i64;
        let mut delta_credits: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        let mut loops = 0u32;
        let mut may_have_more = false;

        loop {
            loops += 1;
            if loops > 50 { break; }

            let (txt, last_ts_hdr, more) = fetch_delta_once(relay_base, date, since, max_lines).await?;
            may_have_more = more;

            for ln in txt.lines() {
                let t = ln.trim();
                if t.is_empty() { continue; }
                delta_total += 1;

                let v: Value = match serde_json::from_str(t) { Ok(x) => x, Err(_) => continue };
                let ts = extract_ts_unix_ms_from_ssr(&v);
                let h = line_hash_hex(t);

                if ts == ent.last_ts_unix_ms && seen.contains(&h) {
                    continue;
                }
                if ts > ent.last_ts_unix_ms {
                    ent.last_ts_unix_ms = ts;
                    seen.clear();
                }
                if ts == ent.last_ts_unix_ms {
                    seen.insert(h.clone());
                }

                let payload = match v.get("receipt_payload") { Some(p) => p, None => continue };
                let dev = match payload.get("device_id").and_then(|x| x.as_str()) { Some(d) => d, None => continue };
                let delta = payload.get("credits_delta_micro").and_then(|x| x.as_i64()).unwrap_or(0);
                *delta_credits.entry(dev.to_string()).or_insert(0) += delta;
            }

            if last_ts_hdr > since { since = last_ts_hdr; }
            if !may_have_more || txt.trim().is_empty() { break; }
        }

        ent.seen_hashes_at_last_ts = seen.iter().take(5000).cloned().collect();
        save_cursor(&cur)?;

        let credits_devices = delta_credits.len() as i64;
        let credits_total_micro: i64 = delta_credits.values().sum();

        let mut snapshot_sha256 = None;
        if let Ok(snap) = fetch_snapshot_json(relay_base, date).await {
            if let Some(h) = snap.get("ssr_sha256").and_then(|v| v.as_str()) {
                snapshot_sha256 = Some(h.to_string());
            }
        }

        return Ok(serde_json::json!({
            "ok": true,
        "mode": "full",
            "exit_code": 0,
            "mode": "delta",
            "date": date,
            "delta_ssr_total": delta_total,
            "delta_credits_devices": credits_devices,
            "delta_credits_total_micro": credits_total_micro,
            "cursor_last_ts_unix_ms": ent.last_ts_unix_ms,
            "snapshot_sha256": snapshot_sha256,
            "relay_base_url": relay_base
        }));
    }

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


async fn fetch_final_json(relay_base: &str, date: &str) -> Result<serde_json::Value> {
    let url = format!("{}/v1/ledger/final/{}", relay_base.trim_end_matches('/'), date);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(PAGE_TIMEOUT_SECS))
        .build()?;
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("final snapshot fetch failed: {}", resp.status()));
    }
    let txt = resp.text().await?;
    Ok(serde_json::from_str(&txt)?)
}

fn canonical_json_bytes_local(v: &Value) -> Vec<u8> {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(map) => {
                let mut keys: Vec<_> = map.keys().cloned().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), sort(&map[&k]));
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            _ => v.clone()
        }
    }
    serde_json::to_vec(&sort(v)).unwrap()
}

fn verify_final_snapshot_sig(final_env: &Value) -> Result<bool> {
    let payload = final_env.get("final_payload").ok_or_else(|| anyhow!("missing final_payload"))?;
    let pk_b64 = final_env.get("server_pubkey_b64").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("missing server_pubkey_b64"))?;
    let sig_b64 = final_env.get("server_sig_b64").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("missing server_sig_b64"))?;

    let pk_bytes = B64.decode(pk_b64)?;
    let pk = VerifyingKey::from_bytes(&pk_bytes.try_into().map_err(|_| anyhow!("bad pk bytes"))?)
        .map_err(|_| anyhow!("bad pk"))?;

    let sig_bytes = B64.decode(sig_b64)?;
    let sig = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| anyhow!("bad sig bytes"))?);

    let canon = canonical_json_bytes_local(payload);
    let msg = Sha256::digest(&canon);

    Ok(pk.verify(&msg, &sig).is_ok())
}

fn read_canonical_pubkey_b64() -> Option<String> {
    let p = std::path::PathBuf::from("ledger/identity/server_pubkey_b64.txt");
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub async fn run_final_verify(relay_base: &str, params: &Value) -> Result<Value> {
    let date = params.get("date").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("missing params.date"))?;
    let final_env = fetch_final_json(relay_base, date).await?;

    let sig_ok = verify_final_snapshot_sig(&final_env)?;
    let pk_b64 = final_env.get("server_pubkey_b64").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let canonical_pk = read_canonical_pubkey_b64();
    let pk_match = canonical_pk.as_ref().map(|c| c == &pk_b64);

    // optional: verify inbox sha matches final_payload.ssr_sha256 if local inbox file exists
    let mut inbox_match = None;
    let inbox_path = std::path::PathBuf::from("ledger/inbox").join(format!("{}.ssr.jsonl", date));
    if inbox_path.exists() {
        let bytes = std::fs::read(&inbox_path)?;
        let inbox_sha = sha256_hex_bytes(&bytes);
        let expected = final_env.get("final_payload").and_then(|p| p.get("ssr_sha256")).and_then(|v| v.as_str()).map(|s| s.to_string());
        inbox_match = expected.map(|e| e == inbox_sha);
    }

    Ok(serde_json::json!({
        "ok": sig_ok && pk_match.unwrap_or(true),
        "exit_code": if sig_ok && pk_match.unwrap_or(true) { 0 } else { 2 },
        "date": date,
        "final_sig_ok": sig_ok,
        "server_pubkey_b64": pk_b64,
        "canonical_pubkey_b64": canonical_pk,
        "pubkey_matches_canonical": pk_match,
        "inbox_sha_matches_final": inbox_match,
        "relay_base_url": relay_base
    }))
}
