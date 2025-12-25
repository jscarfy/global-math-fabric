mod rw_eq_v1;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
pub enum JobInput {
    #[serde(rename="pow_v1")]
    PowV1 { seed_hex: String, difficulty: u32 },

    #[serde(rename="poly_identity_v1")]
    PolyIdentityV1 { vars: Vec<String>, lhs: Vec<Term>, rhs: Vec<Term> },

    #[serde(rename="rw_eq_v1")]
    RwEqV1 { theory: String, start: rw_eq_v1::Expr, goal: rw_eq_v1::Expr, max_steps: u32, max_nodes: u32 },

    #[serde(rename="rw_eq_v2")]
    RwEqV2 {
        theory: String,
        start: rw_eq_v1::Expr,
        goal: rw_eq_v1::Expr,
        max_steps: u32,
        max_nodes: u32,
        challenge_seed_hex: String,
        challenge_pow_difficulty: u32,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
pub enum JobOutput {
    #[serde(rename="pow_v1_result")]
    PowV1Result { nonce: u64, hash_hex: String },

    #[serde(rename="poly_identity_v1_result")]
    PolyIdentityV1Result { ok: bool, nf: Vec<Term>, hash: String },

    #[serde(rename="rw_eq_v1_result")]
    RwEqV1Result { ok: bool, final_: rw_eq_v1::Expr, steps: Vec<rw_eq_v1::Step>, stats: rw_eq_v1::Stats },

    #[serde(rename="rw_eq_v2_result")]
    RwEqV2Result {
        ok: bool,
        final_: rw_eq_v1::Expr,
        steps: Vec<rw_eq_v1::Step>,
        stats: rw_eq_v1::Stats,
        transcript_sha256: String,
        pow_nonce: u64,
        pow_hash_hex: String,
    },

    #[serde(rename="gmf_error")]
    Error { message: String },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Term {
    pub c: i64,
    pub e: Vec<u32>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn leading_zero_bits(d: &[u8;32]) -> u32 {
    let mut count = 0u32;
    for b in d.iter() {
        if *b == 0 { count += 8; continue; }
        count += b.leading_zeros();
        break;
    }
    count
}

fn pow_hash(seed_bytes: &[u8], nonce: u64) -> [u8;32] {
    let mut h = Sha256::new();
    h.update(seed_bytes);
    h.update(nonce.to_le_bytes());
    let out = h.finalize();
    let mut a = [0u8;32];
    a.copy_from_slice(&out[..]);
    a
}

fn parse_seed_hex(seed_hex: &str) -> Result<Vec<u8>, String> {
    hex::decode(seed_hex.trim().to_lowercase()).map_err(|e| format!("bad seed_hex: {e}"))
}

fn pow_search(seed_hex: &str, difficulty: u32) -> Result<JobOutput, String> {
    let seed = parse_seed_hex(seed_hex)?;
    let mut nonce: u64 = 0;
    loop {
        let d = pow_hash(&seed, nonce);
        if leading_zero_bits(&d) >= difficulty {
            return Ok(JobOutput::PowV1Result { nonce, hash_hex: hex::encode(d) });
        }
        nonce = nonce.wrapping_add(1);
        if nonce == 0 { return Err("nonce wrapped; difficulty too high".to_string()); }
    }
}

fn normalize_terms(mut terms: Vec<Term>) -> Vec<Term> {
    terms.retain(|t| t.c != 0);
    terms.sort_by(|a,b| a.e.cmp(&b.e));
    let mut out: Vec<Term> = Vec::new();
    for t in terms {
        if let Some(last) = out.last_mut() {
            if last.e == t.e { last.c += t.c; continue; }
        }
        out.push(t);
    }
    out.retain(|t| t.c != 0);
    for t in out.iter_mut() { while t.e.last().copied() == Some(0) { t.e.pop(); } }
    out.sort_by(|a,b| a.e.cmp(&b.e).then(a.c.cmp(&b.c)));
    out
}

fn poly_identity(vars: &[String], lhs: &[Term], rhs: &[Term]) -> Result<JobOutput, String> {
    let n = vars.len();
    let mut diff: Vec<Term> = Vec::new();
    for t in lhs.iter() {
        if t.e.len() > n { return Err("lhs term exponent longer than vars".into()); }
        diff.push(t.clone());
    }
    for t in rhs.iter() {
        if t.e.len() > n { return Err("rhs term exponent longer than vars".into()); }
        let mut u = t.clone();
        u.c = -u.c;
        diff.push(u);
    }
    let nf = normalize_terms(diff);
    let nf_json = serde_json::to_vec(&nf).map_err(|e| e.to_string())?;
    let hash = sha256_hex(&nf_json);
    Ok(JobOutput::PolyIdentityV1Result { ok: nf.is_empty(), nf, hash })
}

pub fn run_job_json(input_json: &str) -> JobOutput {
    let ji: Result<JobInput, _> = serde_json::from_str(input_json);
    match ji {
        Err(e) => JobOutput::Error { message: format!("bad input json: {e}") },

        Ok(JobInput::PowV1{seed_hex, difficulty}) => {
            pow_search(&seed_hex, difficulty).unwrap_or_else(|msg| JobOutput::Error{ message: msg })
        }

        Ok(JobInput::PolyIdentityV1{vars, lhs, rhs}) => {
            poly_identity(&vars, &lhs, &rhs).unwrap_or_else(|msg| JobOutput::Error{ message: msg })
        }

        Ok(JobInput::RwEqV1{theory, start, goal, max_steps, max_nodes}) => {
            if theory != "ring_lite_v1" {
                return JobOutput::Error{ message: "unsupported theory".to_string() };
            }
            match rw_eq_v1::solve_rw_eq_v1(start, goal, max_steps, max_nodes) {
                rw_eq_v1::Output::Ok{ok, final_, steps, stats} => JobOutput::RwEqV1Result{ ok, final_, steps, stats },
                rw_eq_v1::Output::Err{message} => JobOutput::Error{ message },
            }
        }

        Ok(JobInput::RwEqV2{theory, start, goal, max_steps, max_nodes, challenge_seed_hex, challenge_pow_difficulty}) => {
            if theory != "ring_lite_v1" {
                return JobOutput::Error{ message: "unsupported theory".to_string() };
            }
            match rw_eq_v1::solve_rw_eq_v1(start.clone(), goal.clone(), max_steps, max_nodes) {
                rw_eq_v1::Output::Err{message} => JobOutput::Error{ message },
                rw_eq_v1::Output::Ok{ok, final_, steps, stats} => {
                    let tsha = match rw_eq_v1::transcript_sha256_hex(&start, &goal, &steps) {
                        Ok(x) => x,
                        Err(e) => return JobOutput::Error{ message: format!("transcript hash err: {e}") }
                    };
                    let (nonce, pow_hex) = match rw_eq_v1::solve_pow_for_transcript(&challenge_seed_hex, &tsha, challenge_pow_difficulty) {
                        Ok(x) => x,
                        Err(e) => return JobOutput::Error{ message: format!("pow err: {e}") }
                    };
                    JobOutput::RwEqV2Result{
                        ok,
                        final_,
                        steps,
                        stats,
                        transcript_sha256: tsha,
                        pow_nonce: nonce,
                        pow_hash_hex: pow_hex,
                    }
                }
            }
        }
    }
}
