use axum::{routing::post, Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{env, fs::OpenOptions, io::Write, net::SocketAddr, path::PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use gmf_receipts::{jcs_canonicalize, sha256, sha256_hex};

#[derive(Debug, Deserialize)]
struct ClaimEnvelope {
    consent_token_json: Option<String>,

    protocol: String,                 // "gmf/receipt/v1"
    claim_payload: Value,             // payload to canonicalize+hash
    device_pubkey_b64: String,
    device_sig_b64: String,           // Ed25519 over sha256(jcs(claim_payload))
}

#[derive(Debug, Serialize)]
struct ServerSignedReceipt {
    protocol: String,                 // "gmf/ssr/v1"
    receipt_payload: Value,           // payload (canonicalized) - signed below
    server_pubkey_b64: String,
    server_sig_b64: String,
}

/// Minimal credit formula (MVP):
/// credits_delta_micro = verified_cpu_ms / 1000  (1 microcredit per 1s CPU)
/// You can replace this with policy v1 weights later (still SSR-signed).
fn compute_credits_micro(claim_payload: &Value) -> i64 {
    let cpu_ms = claim_payload
        .get("metrics").and_then(|m| m.get("cpu_ms")).and_then(|v| v.as_i64()).unwrap_or(0);
    (cpu_ms / 1000).max(0)
}

fn verify_claim(claim: &ClaimEnvelope) -> anyhow::Result<String> {
    // verify device signature
    let pk_bytes = B64.decode(&claim.device_pubkey_b64)?;
    let pk = VerifyingKey::from_bytes(&pk_bytes.try_into().map_err(|_| anyhow::anyhow!("bad pk"))?)
        .map_err(|_| anyhow::anyhow!("bad pk parse"))?;
    let sig_bytes = B64.decode(&claim.device_sig_b64)?;
    let sig = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| anyhow::anyhow!("bad sig"))?);

    let canon = jcs_canonicalize(&claim.claim_payload);
    let msg = sha256(&canon);
    pk.verify(&msg, &sig).map_err(|_| anyhow::anyhow!("signature invalid"))?;

    // claim_id = sha256(jcs(payload))
    Ok(hex::encode(msg))
}


fn verify_consent(consent_token_json: &str, device_pubkey_b64: &str, device_id_expected: &str) -> anyhow::Result<()> {
    let token_v: serde_json::Value = serde_json::from_str(consent_token_json)?;
    let payload = token_v.get("consent_payload").ok_or_else(|| anyhow::anyhow!("missing consent_payload"))?;
    let sig_b64 = token_v.get("device_sig_b64").and_then(|v| v.as_str()).ok_or_else(|| anyhow::anyhow!("missing device_sig_b64"))?;

    // check device_id matches
    let device_id = payload.get("device_id").and_then(|v| v.as_str()).ok_or_else(|| anyhow::anyhow!("missing device_id"))?;
    if device_id != device_id_expected {
        return Err(anyhow::anyhow!("device_id mismatch"));
    }

    // verify signature over sha256(JCS(payload)) — for MVP we reuse our Rust JCS canonicalizer (same idea as RFC8785)
    let canon = jcs_canonicalize(payload);
    let msg = sha256(&canon);

    let pk_bytes = B64.decode(device_pubkey_b64)?;
    let pk = VerifyingKey::from_bytes(&pk_bytes.try_into().map_err(|_| anyhow::anyhow!("bad pk"))?)
        .map_err(|_| anyhow::anyhow!("bad pk parse"))?;

    let sig_bytes = B64.decode(sig_b64)?;
    let sig = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| anyhow::anyhow!("bad sig"))?);
    pk.verify(&msg, &sig).map_err(|_| anyhow::anyhow!("consent signature invalid"))?;
    Ok(())
}

fn device_id_from_pubkey_b64(pubkey_b64: &str) -> anyhow::Result<String> {
    let pk_bytes = B64.decode(pubkey_b64)?;
    Ok(sha256_hex(&pk_bytes))
}

fn read_policy_id(policy_path: &PathBuf) -> anyhow::Result<String> {
    let bytes = std::fs::read(policy_path)?;
    Ok(sha256_hex(&bytes))
}

async fn post_claim(Json(claim): Json<ClaimEnvelope>) -> Result<Json<ServerSignedReceipt>, (axum::http::StatusCode, String)> {
    if claim.protocol != "gmf/receipt/v1" {
        return Err((axum::http::StatusCode::BAD_REQUEST, "bad protocol".into()));
    }

    let policy_path = PathBuf::from(env::var("GMF_POLICY_PATH").unwrap_or_else(|_| "protocol/credits/v1/CREDITS_POLICY.md".into()));
    let policy_id = read_policy_id(&policy_path).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let claim_id = verify_claim(&claim).map_err(|e| (axum::http::StatusCode::UNAUTHORIZED, e.to_string()))?;
    let device_id = device_id_from_pubkey_b64(&claim.device_pubkey_b64)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;

    
    // consent required
    let consent = claim.consent_token_json.as_deref().ok_or_else(|| (axum::http::StatusCode::FORBIDDEN, "missing consent token".into()))?;
    verify_consent(consent, &claim.device_pubkey_b64, &device_id)
        .map_err(|e| (axum::http::StatusCode::FORBIDDEN, e.to_string()))?;

    let credits = compute_credits_micro(&claim.claim_payload);


    let server_sk_b64 = env::var("GMF_SERVER_SK_B64").map_err(|_| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "missing GMF_SERVER_SK_B64".into()))?;
    let sk_bytes = B64.decode(&server_sk_b64).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let sk = SigningKey::from_bytes(&sk_bytes.try_into().map_err(|_| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "bad server sk".into()))?);
    let pk = VerifyingKey::from(&sk);
    let server_pubkey_b64 = B64.encode(pk.to_bytes());

    // SSR payload (authoritative)
    let now = Utc::now().to_rfc3339();
    let receipt_payload = serde_json::json!({
        "protocol": "gmf/ssr_payload/v1",
        "policy_id": policy_id,
        "claim_id": claim_id,
        "device_id": device_id,
        "task_id": claim.claim_payload.get("task_id").cloned().unwrap_or(Value::String("unknown".into())),
        "accepted_artifacts": claim.claim_payload.get("artifacts").cloned().unwrap_or(Value::Array(vec![])),
        "credits_delta_micro": credits,
        "reason_code": if credits > 0 { "verified_cpu_ms" } else { "zero" },
        "issued_at": now
    });

    let canon = jcs_canonicalize(&receipt_payload);
    let msg = sha256(&canon);
    let sig: Signature = sk.sign(&msg);
    let server_sig_b64 = B64.encode(sig.to_bytes());

    let ssr = ServerSignedReceipt {
        protocol: "gmf/ssr/v1".into(),
        receipt_payload,
        server_pubkey_b64: server_pubkey_b64.clone(),
        server_sig_b64: server_sig_b64.clone(),
    };

    // Append SSR to today's inbox
    let date = Utc::now().date_naive().to_string();
    let inbox_dir = PathBuf::from("ledger/inbox");
    std::fs::create_dir_all(&inbox_dir).map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let path = inbox_dir.join(format!("{date}.ssr.jsonl"));

    let mut f = OpenOptions::new().create(true).append(true).open(&path)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    writeln!(f, "{}", serde_json::to_string(&ssr).unwrap())
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(ssr))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = Router::new().route("/v1/claims", post(post_claim));
    let host = env::var("GMF_RELAY_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = env::var("GMF_RELAY_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8787);
    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    eprintln!("gmf_relay listening on http://{addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}
