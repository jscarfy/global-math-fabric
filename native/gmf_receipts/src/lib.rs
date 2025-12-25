use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

pub fn jcs_canonicalize(json: &Value) -> Vec<u8> {
    // RFC8785-compatible canonical JSON bytes
    serde_json_canonicalizer::to_vec(json).expect("canonicalize")
}

pub fn generate_device_keypair_b64() -> (String, String) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = VerifyingKey::from(&sk);
    let pk_b64 = B64.encode(pk.to_bytes());
    let sk_b64 = B64.encode(sk.to_bytes());
    (pk_b64, sk_b64)
}

pub fn sign_json_sha256_b64(private_key_b64: &str, json_payload: &Value) -> String {
    let sk_bytes = B64.decode(private_key_b64).expect("b64 sk");
    let sk = SigningKey::from_bytes(&sk_bytes.try_into().expect("32b sk"));
    let canon = jcs_canonicalize(json_payload);
    let msg = sha256(&canon);
    let sig: Signature = sk.sign(&msg);
    B64.encode(sig.to_bytes())
}

pub fn verify_json_sha256_b64(public_key_b64: &str, json_payload: &Value, sig_b64: &str) -> bool {
    let pk_bytes = B64.decode(public_key_b64).expect("b64 pk");
    let pk = VerifyingKey::from_bytes(&pk_bytes.try_into().expect("32b pk")).expect("pk");
    let sig_bytes = B64.decode(sig_b64).expect("b64 sig");
    let sig = Signature::from_bytes(&sig_bytes.try_into().expect("64b sig"));
    let canon = jcs_canonicalize(json_payload);
    let msg = sha256(&canon);
    pk.verify(&msg, &sig).is_ok()
}

/// CT-style Merkle hashing (RFC6962): leaf=H(0x00||entry), node=H(0x01||L||R)
pub fn merkle_root_ct_style(entry_hashes: &[[u8;32]]) -> [u8;32] {
    fn leaf(h: &[u8;32]) -> [u8;32] {
        let mut v = Vec::with_capacity(1+32);
        v.push(0x00);
        v.extend_from_slice(h);
        sha256(&v)
    }
    fn node(l: &[u8;32], r: &[u8;32]) -> [u8;32] {
        let mut v = Vec::with_capacity(1+32+32);
        v.push(0x01);
        v.extend_from_slice(l);
        v.extend_from_slice(r);
        sha256(&v)
    }

    if entry_hashes.is_empty() {
        // define empty root as sha256("") (simple, deterministic)
        return sha256(b"");
    }
    let mut level: Vec<[u8;32]> = entry_hashes.iter().map(leaf).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len()+1)/2);
        let mut i = 0;
        while i < level.len() {
            if i+1 < level.len() {
                next.push(node(&level[i], &level[i+1]));
            } else {
                next.push(level[i]); // odd carry
            }
            i += 2;
        }
        level = next;
    }
    level[0]
}
