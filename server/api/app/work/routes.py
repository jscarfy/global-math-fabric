GMF_AUDIT_CHUNK_SIZE = int(os.environ.get('GMF_AUDIT_CHUNK_SIZE','32768'))
from fastapi.responses import PlainTextResponse
from fastapi.responses import JSONResponse
import random
import base64
import hashlib
from app.work.db.models import LeaseUse, LeaseChallenge
import os
from app.credits.ledger import record_receipt_v1
import json
from pathlib import Path
import os, json, uuid, hashlib, datetime, base64
from fastapi import APIRouter, HTTPException
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app.enroll import verify as verify_enroll
from sqlalchemy import and_
from .db.work_db import SessionWork
from .db.models import Job, JobLease, WorkResult, Device, DeviceDaily

from app.crypto.ledger import append_envelope_line
from app.crypto.governance import load_governance_or_die

from .validators.toy_math import validate as validate_toy_math
from .validators.lean_check import validate as validate_lean_check

router = APIRouter(prefix="/work", tags=["work"])

LEASE_SECONDS = int(os.environ.get("GMF_WORK_LEASE_SECONDS", "300"))

def _now():
    return datetime.datetime.utcnow()

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _b64dec(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def _verify_device_sig(pub_b64: str, msg: str, sig_b64: str) -> bool:
    try:
        pk_bytes = _b64dec(pub_b64)
        if len(pk_bytes) != 32:
            return False
        pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
        pk.verify(_b64dec(sig_b64), msg.encode("utf-8"))
        return True
    except Exception:
        return False

def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _utc_day() -> str:
    return _now().strftime("%Y-%m-%d")

def _csv_norm(sv: str) -> str:
    parts = [x.strip() for x in (sv or "").split(",")]
    parts = [x for x in parts if x]
    # stable order
    parts = sorted(set(parts))
    return ",".join(parts)

def _device_get_or_create(db: Session, device_id: str) -> Device:
    d = db.query(Device).filter(Device.device_id == device_id).first()
    if not d:
        d = Device(device_id=device_id, platform="unknown", has_lean=False, ram_mb=0, disk_mb=0, topics_csv="", meta_json="{}")
        db.add(d); db.commit()
    return d

def _quota_daily_limit() -> int:
    return int(os.environ.get("GMF_DEVICE_DAILY_CREDIT_LIMIT", "0"))  # 0 => unlimited

def _device_daily_row(db: Session, device_id: str) -> DeviceDaily:
    day = _utc_day()
    rid = f"{device_id}|{day}"
    row = db.query(DeviceDaily).filter(DeviceDaily.id == rid).first()
    if not row:
        row = DeviceDaily(id=rid, device_id=device_id, day=day, credits_awarded=0)
        db.add(row); db.commit()
    return row


def _goal_key(kind: str, payload: dict) -> str | None:
    if kind == "lean_check":
        imports = payload.get("imports") or []
        stmt = str(payload.get("statement") or "")
        obj = {"imports": imports, "statement": stmt}
        return _sha256_hex(_canon(obj))
    if kind == "audit_lean_check":
        # audit payload already contains goal_key
        gk = payload.get("goal_key")
        return str(gk) if gk else None
    return None

def _validator_for(kind: str):
    if kind == "toy_math":
        return validate_toy_math
    if kind == "lean_check":
        return validate_lean_check
    return None

@router.post("/jobs/create")
def create_job(kind: str, payload: dict, credits: int = 1, topic: str = "", requires_lean: bool = False, min_ram_mb: int = 0, min_disk_mb: int = 0):
    db: Session = SessionWork()
    try:
        jid = str(uuid.uuid4())
        j = Job(job_id=jid, kind=kind, payload_json=_canon(payload), credits=int(credits), status="open")
        j.topic = (topic.strip() or None)
        j.requires_lean = bool(requires_lean)
        j.min_ram_mb = int(min_ram_mb)
        j.min_disk_mb = int(min_disk_mb)
        try:
            j.goal_key = _goal_key(kind, payload)
        except Exception:
            j.goal_key = None
        db.add(j); db.commit()
        return {"ok": True, "job_id": jid}
    finally:
        db.close()

@router.get("/jobs/pull")
def pull_job(device_id: str, topics: str = ""):
    """
    Lease one open job. If none, returns ok=true + job=null.
    """
    db: Session = SessionWork()
    try:
        d = _device_get_or_create(db, device_id)
        d.last_seen_at = _now()
        db.add(d); db.commit()
        # topics preference: query param overrides device setting if provided
        topics_csv = _csv_norm(topics) if topics.strip() else (d.topics_csv or "")
        allowed_topics = set([t for t in topics_csv.split(",") if t])
        # find open job matching capabilities + topic
        q = db.query(Job).filter(Job.status == "open")
        # capability filters
        q = q.filter((Job.requires_lean == False) | (Job.requires_lean == True))
        # we'll enforce requires_lean manually because sqlite bool semantics can vary
        candidates = q.order_by(Job.created_at.asc()).limit(200).all()
        j = None
        for cand in candidates:
            if cand.requires_lean and not bool(d.has_lean):
                continue
            if int(cand.min_ram_mb or 0) > int(d.ram_mb or 0):
                continue
            if int(cand.min_disk_mb or 0) > int(d.disk_mb or 0):
                continue
            if cand.topic and allowed_topics and cand.topic not in allowed_topics:
                continue
            j = cand
            break
        if not j:
            return {"ok": True, "job": None}

        lease_id = str(uuid.uuid4())

        # challenge nonce verification (bind submit to issued lease)

        lc = _lease_challenge_get(db, lease_id)
        # policy hash binding: client must echo current policy_hash
        sub = submit_obj if 'submit_obj' in locals() else (submission if 'submission' in locals() else {})
        submitted_policy = sub.get('policy_hash')
        submitted_sig_spec = (sub.get('sig_spec_hash') or '').strip().lower()
        if not submitted_sig_spec:
            accepted = False; reason = 'sig_spec_hash_missing'; awarded_credits = 0

        # --- Credits receipt (signed, append-only) ---
        try:
            if accepted and int(awarded_credits) > 0 and isinstance(job_input, dict):
                policy_hash = str(os.environ.get("GMF_POLICY_HASH",""))
                verifier_name = "server_verify_job_output_v1"
                verifier_version = "v1"
                verifier_digest_sha256 = hashlib.sha256(b"server_verify_job_output_v1:v1").hexdigest()

                # best-effort gather ids
                _job_id = str(job_input.get("seed_hex") or job_input.get("kind") or "job")
                _lease_id = str(sub.get("lease_id") or lease.get("lease_id") or lease.get("id") or "lease")
                _job_kind = str(job_input.get("kind") or "unknown")

                device_pk = str(sub.get("device_pk_ed25519") or "")
                device_sig = str(sub.get("device_sig") or sub.get("device_sig_over_submit_sha256") or "")

                audit_rate = float((lease.get("audit_spec") or {}).get("rate", 0.0))
                audit_chunk_size = int((lease.get("audit_spec") or {}).get("chunk_size", 0))
                audit_idx0 = True

                record_receipt_v1(
                    policy_hash=policy_hash,
                    verifier_name=verifier_name,
                    verifier_version=verifier_version,
                    verifier_digest_sha256=verifier_digest_sha256,
                    job_id=_job_id,
                    lease_id=_lease_id,
                    job_kind=_job_kind,
                    job_input_json=json.dumps(job_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                    job_output_json=str(output),
                    device_pk_ed25519=device_pk,
                    device_sig_over_submit_sha256=device_sig,
                    audit_rate=audit_rate,
                    audit_chunk_size=audit_chunk_size,
                    audit_sample_idx0_included=audit_idx0,
                    awarded_credits=int(awarded_credits),
                )
        except Exception as _e:
            # never fail submit due to ledger write; but keep logs
            try:
                print("credit receipt error:", _e)
            except Exception:
                pass
        elif submitted_sig_spec != str(GMF_SIG_SPEC_HASH).lower():
            accepted = False; reason = 'sig_spec_hash_mismatch'; awarded_credits = 0
        # device signature verification (anti-credit-theft)
        device_sig_alg = (sub.get('device_sig_alg') or sub.get('sig_alg') or 'ed25519').strip().lower()
        device_sig_b64 = (sub.get('device_sig') or sub.get('sig') or '').strip()
        # load device pubkey from DB (if present)
        dev_pub = ''
        try:
            dev = _device_get_or_none(db, device_id) if '_device_get_or_none' in globals() else None
            dev_pub = (getattr(dev, 'device_pubkey_ed25519', '') or '').strip().lower() if dev is not None else ''
        except Exception:
            dev_pub = ''
        # Build canonical signed message (covers policy+nonce+merkle fields)
        sig_msg_obj = {
            'device_id': device_id,
            'lease_id': lease_id,
            'job_id': job_id,
            'policy_hash': submitted_policy,
            'challenge_nonce': sub.get('challenge_nonce') or sub.get('nonce'),
            'bundle_format': sub.get('bundle_format'),
            'header_sha256': sub.get('header_sha256'),
            'merkle_root_hex': sub.get('merkle_root_hex') or sub.get('lean_trace_merkle_root'),
            'num_chunks': sub.get('num_chunks'),
            'sample_indices': [int(x.get('idx')) for x in (sub.get('samples') or []) if isinstance(x, dict) and 'idx' in x],
            'output': sub.get('output'),
        }
        sig_msg = _sigmsg_v1_bytes(sig_msg_obj)
        # Enforce if required, or if device has pubkey on file
        if (GMF_REQUIRE_DEVICE_SIG or dev_pub):
            if not dev_pub:
                accepted = False; reason = 'device_pubkey_missing'; awarded_credits = 0
            elif not device_sig_b64:
                accepted = False; reason = 'device_sig_missing'; awarded_credits = 0
            elif device_sig_alg != 'ed25519':
                accepted = False; reason = 'device_sig_alg_unsupported'; awarded_credits = 0
            else:
                ok = _verify_device_sig_ed25519(dev_pub, sig_msg, device_sig_b64)
                if not ok:
                    accepted = False; reason = 'device_sig_invalid'; awarded_credits = 0
        if not submitted_policy:
            accepted = False
            reason = 'policy_hash_missing'
            awarded_credits = 0
        elif str(submitted_policy).lower() != str(GMF_POLICY_HASH).lower():
            accepted = False
            reason = 'policy_hash_mismatch'
            awarded_credits = 0
        # bind policy to this lease (prevents cross-policy replay)
        if accepted and lc is not None:
            lease_pol = str(getattr(lc,'policy_hash','') or '').lower()
            if lease_pol and lease_pol != str(GMF_POLICY_HASH).lower():
                accepted = False
                reason = 'lease_policy_hash_mismatch'
                awarded_credits = 0
            elif lease_pol and str(submitted_policy).lower() != lease_pol:
                accepted = False
                reason = 'submitted_policy_not_equal_lease_policy'
                awarded_credits = 0



        if lc is not None:

            submitted_nonce = (submit_obj.get('challenge_nonce') if 'submit_obj' in locals() else (submission.get('challenge_nonce') if 'submission' in locals() else None))

            if not submitted_nonce or str(submitted_nonce) != str(lc.nonce_hex):

                accepted = False

                reason = 'challenge_bad_nonce'

                awarded_credits = 0

        challenge_nonce = _challenge_nonce_hex()

        required_fields = _job_required_fields(job_obj if 'job_obj' in locals() else job)

        audit_required = _audit_required(job_obj if 'job_obj' in locals() else job)

        _lease_challenge_put(db, lease_id, device_id, job_id, challenge_nonce, audit_required, required_fields, ts_utc)

        # replay protection: each lease_id can be submitted at most once

        replay = _lease_used(db, lease_id)

        if replay:

            accepted = False

            reason = 'replay_lease_id'

            awarded_credits = 0
        exp = _now() + datetime.timedelta(seconds=LEASE_SECONDS)
        l = JobLease(lease_id=lease_id, job_id=j.job_id, device_id=device_id, expires_at=exp, active=True)
        j.status = "leased"
        db.add(l); db.add(j); db.commit()

        payload = json.loads(j.payload_json)
        return {
            "ok": True,
            "job": {
                "job_id": j.job_id,
                "kind": j.kind,
                "payload": payload,
                "credits": j.credits,
                "lease_id": lease_id,
                "lease_expires_at": exp.replace(tzinfo=datetime.timezone.utc).isoformat()
            }
        }
    finally:
        db.close()

@router.post("/jobs/submit")
def submit_job(device_id: str, lease_id: str, job_id: str, output: dict, device_msg: str = "", device_sig_b64: str = ""):
    """
    Validate output; if accepted, mint signed work_receipt (server-signed) and write into ledger.
    Credits = job.credits if accepted else 0.
    """
    db: Session = SessionWork()
    try:
        lease = db.query(JobLease).filter(and_(JobLease.lease_id==lease_id, JobLease.job_id==job_id, JobLease.device_id==device_id, JobLease.active==True)).first()
        # device signature required (prevents impersonation)
        d = _device_get_or_create(db, device_id)
        if not (d.pubkey_b64 and device_msg and device_sig_b64):
            raise HTTPException(status_code=400, detail="device_sig_required")
        if not _verify_device_sig(d.pubkey_b64, device_msg, device_sig_b64):
            raise HTTPException(status_code=400, detail="device_sig_invalid")
        if not lease:
            raise HTTPException(status_code=400, detail="invalid_lease")
        if lease.expires_at < _now():
            lease.active = False
            # store pubkey if provided
        if device_pubkey_ed25519:
            try:
                dev.device_pubkey_ed25519 = device_pubkey_ed25519
                dev.pubkey_updated_ts_utc = ts_utc
            except Exception:
                pass
        db.commit()
            raise HTTPException(status_code=400, detail="lease_expired")

        job = db.query(Job).filter(Job.job_id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="unknown_job")

        # Canonicalize payload+output to hash
        payload = json.loads(job.payload_json)
        payload_c = _canon(payload)
        output_c = _canon(output)

        vfn = _validator_for(job.kind)
        if not vfn:
            ok, reason = (False, "no_validator")
        else:
            ok, reason = vfn(payload, output)

        # novelty policy (hard rule): first accepted for a goal_key gets full credits; repeats get repeat_factor
        repeat_factor = float(os.environ.get("GMF_REPEAT_FACTOR", "0.1"))
        audit_credits = int(os.environ.get("GMF_AUDIT_CREDITS", "1"))
        awarded = int(job.credits) if ok else 0
        if ok and job.goal_key:
            # if already accepted once for this goal_key, downweight
            prev = db.query(Job).filter(Job.goal_key == job.goal_key, Job.accepted_once == True).first()
            if prev and prev.job_id != job.job_id:
                awarded = max(0, int(round(int(job.credits) * repeat_factor)))

        # attempts
        try:
            job.attempts = int(job.attempts or 0) + 1
        except Exception:
            job.attempts = 1

        # record result
        rid = str(uuid.uuid4())
        wr = WorkResult(
            result_id=rid,
            job_id=job_id,
            device_id=device_id,
            input_sha256=_sha256_hex(payload_c),
            output_sha256=_sha256_hex(output_c),
            output_json=output_c,
            accepted=bool(ok),
            awarded_credits=awarded,
            receipt_id=None
        )
        db.add(wr)

        # close lease
        lease.active = False

        # mark job done if accepted (MVP：接受即 done；否则 reopen 让别人再试)
        if ok:
            job.status = "done"
            job.accepted_once = True
        else:
            job.status = "open"

        db.add(job)
        db.commit()

        # mint receipt only if accepted
        if ok:
            gov = load_governance_or_die()
            d = _device_get_or_create(db, device_id)
            payload_obj = {
                "type": "work_receipt",
                "enroll_ref": d.enroll_ref,
                "policy_version": d.policy_version,
                "receipt_id": str(uuid.uuid4()),
                "job_id": job_id,
                "device_id": device_id,
                "job_kind": job.kind,
                "input_sha256": wr.input_sha256,
                "output_sha256": wr.output_sha256,
                "awarded_credits": awarded,
                "rules_sha256": gov["rules_sha256"],
                "issued_at": _now().replace(tzinfo=datetime.timezone.utc).isoformat()
            }
            env = append_envelope_line(payload_obj)
            lim = _quota_daily_limit()
            if lim > 0:
                row = _device_daily_row(db, device_id)
                row.credits_awarded = int(row.credits_awarded or 0) + int(awarded)
                db.add(row); db.commit()
            # create audit job for independent re-check (pays auditors)
            if job.kind == "lean_check" and job.goal_key:
                audit_payload = {
                    "goal_key": job.goal_key,
                    "imports": payload.get("imports") if isinstance(payload, dict) else [],
                    "theorem_name": "audit_" + str(payload.get("theorem_name") or "t"),
                    "statement": str(payload.get("statement") or ""),
                    "original_receipt_id": payload_obj["receipt_id"],
                    "proof_script": output.get("proof_script")
                }
                aj = Job(job_id=str(uuid.uuid4()), kind="audit_lean_check", payload_json=_canon(audit_payload), credits=int(audit_credits), status="open")
                aj.goal_key = job.goal_key
                db.add(aj)
                db.commit()
            wr.receipt_id = payload_obj["receipt_id"]
            db.add(wr); db.commit()
            return {"ok": True, "accepted": True, "reason": reason, "awarded_credits": awarded, "receipt": env}

        return {"ok": True, "accepted": False, "reason": reason, "awarded_credits": 0}
    finally:
        db.close()


@router.post("/devices/register")
def device_register(device_id: str, platform: str = "unknown", has_lean: bool = False, ram_mb: int = 0, disk_mb: int = 0, topics: str = "", pubkey_b64: str = "", enroll_token: str = "", meta: dict | None = None):
    """
    Device announces capabilities + preferred topics.
    topics: csv, e.g. "algebra,nt,topology"
    """
    db: Session = SessionWork()
    try:
        d = _device_get_or_create(db, device_id)
        d.platform = platform
        d.has_lean = bool(has_lean)
        d.ram_mb = int(ram_mb)
        d.disk_mb = int(disk_mb)
        # optional immutable enrollment token (binds long-term rules)
        if enroll_token.strip():
            pay = verify_enroll(enroll_token.strip())
            # enforce topics from token if present
            tok_topics = (pay.get("topics") or "")
            if tok_topics:
                topics = tok_topics
            d.policy_version = str(pay.get("policy_version") or "v1")
            d.daily_credit_limit = int(pay.get("daily_credit_limit") or 0)
            d.enroll_ref = _sha256_hex(enroll_token.strip())
        d.topics_csv = _csv_norm(topics)
        if pubkey_b64.strip():
            d.pubkey_b64 = pubkey_b64.strip()
        d.meta_json = _canon(meta or {})
        d.last_seen_at = _now()
        db.add(d); db.commit()
        return {"ok": True, "device_id": device_id, "platform": d.platform, "has_lean": d.has_lean, "topics": d.topics_csv}
    finally:
        db.close()

@router.post("/devices/heartbeat")
def device_heartbeat(device_id: str):
    db: Session = SessionWork()
    try:
        d = _device_get_or_create(db, device_id)
        d.last_seen_at = _now()
        db.add(d); db.commit()
        return {"ok": True, "device_id": device_id}
    finally:
        db.close()

GMF_VERIFICATION_DIR = os.environ.get('GMF_VERIFICATION_DIR', 'ledger/verifications')


def _canon_json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def _sha256_hex_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _verif_path_for_hash(h: str) -> Path:
    h = h.lower()
    d = Path(GMF_VERIFICATION_DIR) / h[:2]
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{h}.json"

def _write_verification_record(rec: dict) -> str:
    b = _canon_json_bytes(rec)
    h = _sha256_hex_bytes(b)
    p = _verif_path_for_hash(h)
    if not p.exists():
        p.write_bytes(b)
    return h


GMF_XLINK_DIR = os.environ.get('GMF_XLINK_DIR', 'ledger/xlinks')

def _require_challenge_fields(job_obj: dict, submit_obj: dict):
    req = job_obj.get("challenge_required_fields") or []
    for k in req:
        if k not in submit_obj or submit_obj.get(k) in (None, "", []):
            return False, f"challenge_missing_field:{k}"
    return True, ""

GMF_AUDIT_BUNDLE_DIR = os.environ.get('GMF_AUDIT_BUNDLE_DIR', 'ledger/audit_bundles')

GMF_AUDIT_DEFAULT_RATE = float(os.environ.get('GMF_AUDIT_DEFAULT_RATE', '0.01'))

def _challenge_nonce_hex(nbytes: int = 16) -> str:
    return os.urandom(nbytes).hex()

def _csv_norm(s: str) -> str:
    parts = [p.strip() for p in (s or "").split(",")]
    parts = [p for p in parts if p]
    # unique keep order
    seen=set(); out=[]
    for p in parts:
        if p not in seen:
            out.append(p); seen.add(p)
    return ",".join(out)

def _job_required_fields(job_obj: dict) -> list[str]:
    # job can define: {"challenge_required_fields":["lean_trace_hash"], "audit_rate":0.02}
    req = job_obj.get("challenge_required_fields") or job_obj.get("challenge", {}).get("required_fields") or []
    if isinstance(req, str):
        req = [x.strip() for x in req.split(",") if x.strip()]
    return [str(x) for x in req]

def _job_audit_rate(job_obj: dict) -> float:
    r = job_obj.get("audit_rate")
    if r is None:
        r = job_obj.get("challenge", {}).get("audit_rate")
    if r is None:
        r = GMF_AUDIT_DEFAULT_RATE
    try:
        r = float(r)
    except Exception:
        r = GMF_AUDIT_DEFAULT_RATE
    if r < 0: r = 0.0
    if r > 1: r = 1.0
    return r

def _audit_required(job_obj: dict) -> bool:
    return random.random() < _job_audit_rate(job_obj)

def _canon_json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def _sha256_hex_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _audit_bundle_path(proof_hash: str) -> Path:
    d = Path(GMF_AUDIT_BUNDLE_DIR)
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{proof_hash}.bin"

def _write_audit_bundle(proof_hash: str, bundle_bytes: bytes) -> dict:
    h = _sha256_hex_bytes(bundle_bytes)
    path = _audit_bundle_path(proof_hash)
    if not path.exists():
        path.write_bytes(bundle_bytes)
    meta = {
        "kind": "gmf_audit_bundle_meta",
        "version": 1,
        "proof_hash": proof_hash,
        "bundle_sha256": h,
        "bytes": len(bundle_bytes),
        "path": str(path),
    }
    (path.with_suffix(".meta.json")).write_bytes(_canon_json_bytes(meta))
    return meta

def _lease_challenge_put(db, lease_id: str, device_id: str, job_id: str, nonce_hex: str, audit_required: bool, required_fields: list[str], ts_utc: str, seed_hex: str = "", chunk_size: int = 65536, sample_k: int = 3, policy_hash: str = ""):
    rf = _csv_norm(",".join(required_fields))
    row = db.query(LeaseChallenge).filter(LeaseChallenge.lease_id == lease_id).first()
    if row is None:
        row = LeaseChallenge(
            lease_id=lease_id, device_id=device_id, job_id=job_id,
            nonce_hex=nonce_hex, seed_hex=seed_hex, chunk_size=int(chunk_size), sample_k=int(sample_k), policy_hash=str(policy_hash),
            audit_required=1 if audit_required else 0, required_fields_csv=rf, created_ts_utc=ts_utc,
        )
        db.add(row)
    else:
        row.nonce_hex = nonce_hex
        row.seed_hex = seed_hex
        row.chunk_size = int(chunk_size)
        row.sample_k = int(sample_k)
        row.policy_hash = str(policy_hash)
        row.audit_required = 1 if audit_required else 0
        row.required_fields_csv = rf
        row.created_ts_utc = ts_utc
    db.commit()

def _lease_challenge_get(db, lease_id: str):
    return db.query(LeaseChallenge).filter(LeaseChallenge.lease_id == lease_id).first()

GMF_MERKLE_CHUNK_SIZE = int(os.environ.get('GMF_MERKLE_CHUNK_SIZE','65536'))

GMF_AUDIT_SAMPLE_K = int(os.environ.get('GMF_AUDIT_SAMPLE_K','3'))

GMF_AUDIT_MIN_CHUNKS = int(os.environ.get('GMF_AUDIT_MIN_CHUNKS','16'))

GMF_AUDIT_TRANSCRIPTS_DIR = os.environ.get('GMF_AUDIT_TRANSCRIPTS_DIR','ledger/audit_transcripts')

def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def _hx(b: bytes) -> str:
    return b.hex()

def _unhex(h: str) -> bytes:
    return bytes.fromhex(h.strip().lower())

def _merkle_parent(left: bytes, right: bytes) -> bytes:
    return _sha256(left + right)

def _merkle_verify_proof(leaf_hash: bytes, proof: list[dict], root_hex: str) -> bool:
    cur = leaf_hash
    for step in proof:
        side = step.get("side")
        sib = _unhex(step.get("h",""))
        if side == "L":
            cur = _merkle_parent(sib, cur)
        elif side == "R":
            cur = _merkle_parent(cur, sib)
        else:
            return False
    return _hx(cur) == root_hex.lower()

def _audit_indices(seed_hex: str, num_chunks: int, k: int) -> list[int]:
    # deterministic indices from seed; ALWAYS include 0 for header chunk.
    # remaining (k-1) indices are derived: idx_i = sha256(seed||i) mod num_chunks, excluding 0 if possible.
    if num_chunks <= 0:
        return [0]
    seed = _unhex(seed_hex)
    out = [0]
    seen = set(out)
    need = max(1, int(k)) - 1
    tries = max(1, need * 5)
    for i in range(tries):
        h = _sha256(seed + i.to_bytes(4, "big"))
        idx = int.from_bytes(h[:8], "big") % num_chunks
        if idx not in seen and idx != 0:
            out.append(idx); seen.add(idx)
        if len(out) >= 1 + need:
            break
    while len(out) < 1 + need:
        out.append(0)
    return out

def _audit_transcript_path(proof_hash: str) -> Path:
    d = Path(GMF_AUDIT_TRANSCRIPTS_DIR)
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{proof_hash}.json"

def _write_audit_transcript(obj: dict) -> None:
    # immutable-ish: if exists, keep
    ph = obj.get("proof_hash","")
    p = _audit_transcript_path(ph)
    if not p.exists():
        p.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")

def _verify_bundle_v1_header(header_bytes: bytes, header_sha256: str) -> tuple[bool,str]:
    # must fit in chunk0; must be utf-8 json
    if not header_bytes or len(header_bytes) > 60000:
        return False, "bundle_header_size_invalid"
    try:
        got = _sha256_hex_bytes(header_bytes)
        if str(got) != str(header_sha256).lower():
            return False, "bundle_header_sha_mismatch"
        txt = header_bytes.decode("utf-8", errors="strict")
        obj = json.loads(txt)
    except Exception:
        return False, "bundle_header_parse_failed"

    if obj.get("kind") != "gmf_trace_bundle_header" or int(obj.get("version",0)) != 1 or obj.get("format") != "gmf_bundle_v1":
        return False, "bundle_header_fields_invalid"

    files = obj.get("files") or []
    if not isinstance(files, list):
        return False, "bundle_header_files_invalid"
    names = {f.get("name") for f in files if isinstance(f, dict)}
    req = {"Main.lean","build.log","versions.json"}
    if not req.issubset(names):
        return False, "bundle_header_missing_required_files"
    return True, ""


GMF_POLICY_PATH = os.environ.get("GMF_POLICY_PATH", "ledger/policies/credit_policy_v2_bundle_v1.md")
GMF_POLICY_HASH_OVERRIDE = os.environ.get("GMF_POLICY_HASH", "").strip()

def _load_policy_hash() -> tuple[str,str]:
    # returns (policy_hash, policy_name)
    policy_name = Path(GMF_POLICY_PATH).name
    if GMF_POLICY_HASH_OVERRIDE:
        return (GMF_POLICY_HASH_OVERRIDE.lower(), policy_name)
    try:
        b = Path(GMF_POLICY_PATH).read_bytes()
        h = hashlib.sha256(b).hexdigest()
        return (h, policy_name)
    except Exception:
        # If policy file missing, we still return a sentinel; but better to fail fast in production.
        h = hashlib.sha256(f"MISSING:{GMF_POLICY_PATH}".encode("utf-8")).hexdigest()
        return (h, policy_name)

GMF_POLICY_HASH, GMF_POLICY_NAME = _load_policy_hash()

def _policy_registry_path() -> Path:
    return Path("ledger/policies/registry.json")

def _build_policy_registry_obj() -> dict:
    pol_dir = Path("ledger/policies")
    items = []
    if pol_dir.exists():
        for f in sorted(pol_dir.glob("*.md")):
            try:
                b = f.read_bytes()
                items.append({"name": f.name, "relpath": str(f), "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)})
            except Exception:
                continue
    return {"kind":"gmf_policy_registry","version":1,"policies":items}

def _load_or_build_policy_registry() -> dict:
    rp = _policy_registry_path()
    if rp.exists():
        try:
            return json.loads(rp.read_text(encoding="utf-8"))
        except Exception:
            pass
    obj = _build_policy_registry_obj()
    try:
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass
    return obj

@router.get("/policy/current")
def policy_current():
    # policy hash/name computed at import time (GMF_POLICY_HASH/GMF_POLICY_NAME)
    # policy_path returned for transparency; clients should not rely on filesystem existence.
    try:
        pb = Path(GMF_POLICY_PATH).read_bytes()
        pb_sha = hashlib.sha256(pb).hexdigest()
    except Exception:
        pb_sha = hashlib.sha256(f"MISSING:{GMF_POLICY_PATH}".encode("utf-8")).hexdigest()

    return JSONResponse({
        "ok": True,
        "policy_hash": GMF_POLICY_HASH,
        "policy_name": GMF_POLICY_NAME,
        "policy_path": GMF_POLICY_PATH,
        "policy_bytes_sha256": pb_sha,
    })

@router.get("/policy/registry")
def policy_registry():
    obj = _load_or_build_policy_registry()
    return JSONResponse({"ok": True, "registry": obj})

@router.get("/policy/by_hash/{policy_hash}")
def policy_by_hash(policy_hash: str):
    policy_hash = (policy_hash or "").strip().lower()
    reg = _load_or_build_policy_registry()
    hit = None
    for it in reg.get("policies", []):
        if str(it.get("sha256","")).lower() == policy_hash:
            hit = it
            break
    return JSONResponse({
        "ok": True,
        "query_hash": policy_hash,
        "found": bool(hit),
        "policy": hit,
        "hint": "Fetch policy file content via git mirror path in 'relpath' (policy text not served here).",
    })

GMF_SERVE_POLICY_TEXT = os.environ.get('GMF_SERVE_POLICY_TEXT','0').strip() in ('1','true','TRUE','yes','YES')

@router.get("/policy/text/{policy_hash}")
def policy_text(policy_hash: str):
    if not GMF_SERVE_POLICY_TEXT:
        return JSONResponse({"ok": False, "error": "policy_text_serving_disabled"}, status_code=403)
    policy_hash = (policy_hash or "").strip().lower()
    reg = _load_or_build_policy_registry()
    hit = None
    for it in reg.get("policies", []):
        if str(it.get("sha256","")).lower() == policy_hash:
            hit = it
            break
    if not hit:
        return JSONResponse({"ok": False, "error": "policy_not_found", "query_hash": policy_hash}, status_code=404)
    pth = Path(hit.get("relpath",""))
    if not pth.exists():
        return JSONResponse({"ok": False, "error": "policy_file_missing", "relpath": str(pth)}, status_code=404)
    txt = pth.read_text(encoding="utf-8", errors="replace")
    # serve as plain text
    return PlainTextResponse(txt, media_type="text/plain; charset=utf-8")

GMF_REQUIRE_DEVICE_SIG = os.environ.get('GMF_REQUIRE_DEVICE_SIG','0').strip() in ('1','true','TRUE','yes','YES')

GMF_DEVICE_SIG_ALG = os.environ.get('GMF_DEVICE_SIG_ALG','ed25519').strip().lower()

def _canon_sig_message(obj: dict) -> bytes:
    # Canonical JSON bytes (stable for signature)
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def _verify_device_sig_ed25519(pubkey_hex: str, msg: bytes, sig_b64: str) -> bool:
    if Ed25519PublicKey is None:
        return False
    try:
        pk = bytes.fromhex(pubkey_hex.strip().lower())
        sig = base64.b64decode(sig_b64)
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except Exception:
        return False

GMF_SIG_SPEC_PATH = os.environ.get('GMF_SIG_SPEC_PATH','ledger/policies/sig_spec_v1.md')

def _load_sig_spec_hash() -> tuple[str,str]:
    p = Path(GMF_SIG_SPEC_PATH)
    name = p.name
    try:
        b = p.read_bytes()
        return (hashlib.sha256(b).hexdigest(), name)
    except Exception:
        return (hashlib.sha256(f"MISSING:{GMF_SIG_SPEC_PATH}".encode("utf-8")).hexdigest(), name)

GMF_SIG_SPEC_HASH, GMF_SIG_SPEC_NAME = _load_sig_spec_hash()

def _sigmsg_v1_bytes(fields: dict) -> bytes:
    # fixed order, key=value\n
    keys = [
        "device_id","lease_id","job_id","policy_hash","sig_spec_hash","challenge_nonce",
        "bundle_format","header_sha256","merkle_root_hex","num_chunks","sample_indices","output_sha256"
    ]
    def val(k):
        v = fields.get(k)
        if v is None:
            return ""
        if k == "sample_indices":
            if isinstance(v, list):
                return ",".join(str(int(x)) for x in v)
            return str(v)
        return str(v)
    lines = []
    for k in keys:
        lines.append(f"{k}={val(k)}\n")
    return "".join(lines).encode("utf-8")

import random

def _make_job_input_v1(topic: str) -> dict:
    # topic can select job families; default -> pow_v1
    if topic == "rw":
        return _make_rw_eq_job_v1()
    if topic == "poly":
        # simple identity: (x+y)^2 == x^2 + 2xy + y^2
        return {
            "kind":"poly_identity_v1",
            "vars":["x","y"],
            "lhs":[{"c":1,"e":[2,0]},{"c":2,"e":[1,1]},{"c":1,"e":[0,2]}],
            "rhs":[{"c":1,"e":[2,0]},{"c":2,"e":[1,1]},{"c":1,"e":[0,2]}],
        }
    # pow difficulty baseline (policy can later vary per device)
    seed = hashlib.sha256(os.urandom(32)).hexdigest()
    return {"kind":"pow_v1","seed_hex":seed,"difficulty":18}

def _verify_job_output_v1(job_input: dict, output_str: str) -> tuple[bool,str,int]:
    """
    returns (ok, reason, credits)
    credits here is baseline; policy can further adjust.
    """
    try:
        out = json.loads(output_str)
    except Exception:
        return (False, "output_not_json", 0)

    kind = (job_input.get("kind") or "").strip()
    ok_kind = (out.get("kind") or "").strip()

    if kind == "pow_v1":
        if ok_kind != "pow_v1_result":
            return (False, "pow_wrong_kind", 0)
        seed_hex = str(job_input.get("seed_hex","")).lower().strip()
        diff = int(job_input.get("difficulty",0))
        try:
            nonce = int(out.get("nonce"))
        except Exception:
            return (False, "pow_bad_nonce", 0)

        # recompute sha256(seed||nonce_le)
        try:
            seed = bytes.fromhex(seed_hex)
        except Exception:
            return (False, "pow_bad_seed", 0)
        h = hashlib.sha256(seed + nonce.to_bytes(8,'little',signed=False)).digest()
        # count leading zero bits
        lz = 0
        for b in h:
            if b == 0:
                lz += 8
                continue
            lz += (8 - len(bin(b)) + 2)  # wrong; patch below
            break
        # fix: pythonic leading_zeros
        lz = 0
        for b in h:
            if b == 0:
                lz += 8
            else:
                lz += (8 - (b.bit_length()))
                break

        if lz < diff:
            return (False, "pow_difficulty_not_met", 0)

        # baseline credits: 2^(diff-10) capped
        credits = 1 << max(0, diff - 10)
        credits = min(credits, 1<<18)
        return (True, "ok", int(credits))

    if kind == "poly_identity_v1":
        if ok_kind != "poly_identity_v1_result":
            return (False, "poly_wrong_kind", 0)
        # recompute nf(lhs-rhs)
        vars_ = job_input.get("vars") or []
        lhs = job_input.get("lhs") or []
        rhs = job_input.get("rhs") or []

        def norm(terms):
            # combine like exponents
            mp = {}
            for t in terms:
                c = int(t.get("c",0))
                e = tuple(int(x) for x in (t.get("e") or []))
                if c == 0: 
                    continue
                mp[e] = mp.get(e,0) + c
            out = []
            for e,c in mp.items():
                if c != 0:
                    out.append({"c":int(c),"e":[int(x) for x in e]})
            out.sort(key=lambda t: (t["e"], t["c"]))
            # trim trailing zeros in e
            for t in out:
                while t["e"] and t["e"][-1] == 0:
                    t["e"].pop()
            out.sort(key=lambda t: (t["e"], t["c"]))
            return out

        diff = []
        for t in lhs:
            diff.append({"c":int(t.get("c",0)),"e":t.get("e") or []})
        for t in rhs:
            diff.append({"c":-int(t.get("c",0)),"e":t.get("e") or []})

        nf = norm(diff)
        claimed_nf = out.get("nf") or []
        if norm(claimed_nf) != nf:
            return (False, "poly_nf_mismatch", 0)

        claimed_ok = bool(out.get("ok", False))
        if claimed_ok != (len(nf) == 0):
            return (False, "poly_ok_flag_wrong", 0)

        # baseline credits ~ size
        credits = min(1000, 10 + 2*len(lhs) + 2*len(rhs) + sum(sum(int(x) for x in (t.get("e") or [])) for t in lhs+rhs))
        return (True, "ok", int(credits))


    if kind == "rw_eq_v1":
        # output expected JSON with kind=rw_eq_v1_result
        if ok_kind != "rw_eq_v1_result":
            return (False, "rw_wrong_kind", 0)

        start = job_input.get("start")
        goal  = job_input.get("goal")
        max_steps = int(job_input.get("max_steps", 0))
        max_nodes = int(job_input.get("max_nodes", 0))
        steps = out.get("steps") or []

        # replay (apply rule at path)
        def nodes(expr):
            if not isinstance(expr, dict): return 0
            t = expr.get("t")
            if t in ("c","v"): return 1
            if t in ("+","*"):
                a = expr.get("a") or []
                return 1 + sum(nodes(x) for x in a)
            return 1

        def canon_key(expr):
            t = expr.get("t")
            if t=="c": return f"c:{int(expr.get('v',0))}"
            if t=="v": return f"v:{expr.get('n','')}"
            if t in ("+","*"):
                ks = [canon_key(x) for x in (expr.get("a") or [])]
                ks.sort()
                return f"{t}(" + ",".join(ks) + ")"
            return "?"

        def get_at(expr, path):
            cur = expr
            for i in path:
                a = cur.get("a") or []
                if int(i) < 0 or int(i) >= len(a): return None
                cur = a[int(i)]
            return cur

        def set_at(expr, path, new_sub):
            if not path: 
                return new_sub
            cur = expr
            for i in path[:-1]:
                a = cur.get("a") or []
                cur = a[int(i)]
            a = cur.get("a") or []
            a[int(path[-1])] = new_sub
            cur["a"] = a
            return expr

        def apply_rule(sub, rule):
            t = sub.get("t")
            if rule=="add_flatten" and t=="+":
                outa=[]
                changed=False
                for x in (sub.get("a") or []):
                    if isinstance(x, dict) and x.get("t")=="+": 
                        outa.extend(x.get("a") or []); changed=True
                    else:
                        outa.append(x)
                if changed: sub["a"]=outa
                return changed

            if rule=="mul_flatten" and t=="*":
                outa=[]
                changed=False
                for x in (sub.get("a") or []):
                    if isinstance(x, dict) and x.get("t")=="*": 
                        outa.extend(x.get("a") or []); changed=True
                    else:
                        outa.append(x)
                if changed: sub["a"]=outa
                return changed

            if rule=="add_sort" and t=="+":
                a = sub.get("a") or []
                before=[canon_key(x) for x in a]
                a.sort(key=canon_key)
                after=[canon_key(x) for x in a]
                sub["a"]=a
                return before!=after

            if rule=="mul_sort" and t=="*":
                a = sub.get("a") or []
                before=[canon_key(x) for x in a]
                a.sort(key=canon_key)
                after=[canon_key(x) for x in a]
                sub["a"]=a
                return before!=after

            if rule=="add_drop0" and t=="+":
                a = [x for x in (sub.get("a") or []) if not (isinstance(x,dict) and x.get("t")=="c" and int(x.get("v",0))==0)]
                if len(a)==0: return {"t":"c","v":0}
                if len(a)==1: return a[0]
                sub["a"]=a
                return True

            if rule=="mul_drop1" and t=="*":
                a = [x for x in (sub.get("a") or []) if not (isinstance(x,dict) and x.get("t")=="c" and int(x.get("v",1))==1)]
                if len(a)==0: return {"t":"c","v":1}
                if len(a)==1: return a[0]
                sub["a"]=a
                return True

            if rule=="mul_annihilate0" and t=="*":
                for x in (sub.get("a") or []):
                    if isinstance(x,dict) and x.get("t")=="c" and int(x.get("v",0))==0:
                        return {"t":"c","v":0}
                return False

            if rule=="add_foldconst" and t=="+":
                s=0; outa=[]; seen=False
                for x in (sub.get("a") or []):
                    if isinstance(x,dict) and x.get("t")=="c":
                        s += int(x.get("v",0)); seen=True
                    else:
                        outa.append(x)
                if seen: outa.append({"t":"c","v":s})
                sub["a"]=outa
                return seen

            if rule=="mul_foldconst" and t=="*":
                prod=1; outa=[]; seen=False
                for x in (sub.get("a") or []):
                    if isinstance(x,dict) and x.get("t")=="c":
                        prod *= int(x.get("v",1)); seen=True
                    else:
                        outa.append(x)
                if seen: outa.append({"t":"c","v":prod})
                sub["a"]=outa
                return seen

            if rule=="distribute_left" and t=="*":
                a = sub.get("a") or []
                if len(a)!=2: return False
                A,B = a[0],a[1]
                if isinstance(B,dict) and B.get("t")=="+":
                    terms=B.get("a") or []
                    return {"t":"+","a":[{"t":"*","a":[A, t]} for t in terms]}
                return False

            if rule=="distribute_right" and t=="*":
                a = sub.get("a") or []
                if len(a)!=2: return False
                B,A = a[0],a[1]
                if isinstance(B,dict) and B.get("t")=="+":
                    terms=B.get("a") or []
                    return {"t":"+","a":[{"t":"*","a":[t, A]} for t in terms]}
                return False

            return False

        # replay
        cur = start
        if not isinstance(cur, dict) or not isinstance(goal, dict):
            return (False, "rw_bad_ast", 0)
        if nodes(cur) > max_nodes:
            return (False, "rw_start_exceeds_max_nodes", 0)
        if len(steps) > max_steps:
            return (False, "rw_too_many_steps", 0)

        for st in steps:
            rule = st.get("rule")
            path = st.get("path") or []
            sub = get_at(cur, path)
            if sub is None or not isinstance(sub, dict):
                return (False, "rw_bad_path", 0)
            applied = apply_rule(sub, rule)
            if applied is False:
                return (False, "rw_rule_not_applicable", 0)
            if isinstance(applied, dict):
                cur = set_at(cur, path, applied)
            if nodes(cur) > max_nodes:
                return (False, "rw_max_nodes_exceeded", 0)

        if cur != goal:
            return (False, "rw_final_mismatch", 0)

        credits = min(5000, 50 + 2*len(steps) + nodes(start)//4)
        return (True, "ok", int(credits))


    return (False, "unknown_job_kind", 0)

def _make_rw_eq_job_v1() -> dict:
    # (x+y)*(x+y) 目标：展开并排序
    start = {"t":"*","a":[{"t":"+","a":[{"t":"v","n":"x"},{"t":"v","n":"y"}]},{"t":"+","a":[{"t":"v","n":"x"},{"t":"v","n":"y"}]}]}
    goal  = {"t":"+","a":[
        {"t":"*","a":[{"t":"v","n":"x"},{"t":"v","n":"x"}]},
        {"t":"*","a":[{"t":"v","n":"x"},{"t":"v","n":"y"}]},
        {"t":"*","a":[{"t":"v","n":"y"},{"t":"v","n":"x"}]},
        {"t":"*","a":[{"t":"v","n":"y"},{"t":"v","n":"y"}]},
    ]}
    return {"kind":"rw_eq_v1","theory":"ring_lite_v1","start":start,"goal":goal,"max_steps":400,"max_nodes":4000}


def _rw_nodes(expr):
    if not isinstance(expr, dict): return 0
    t = expr.get("t")
    if t in ("c","v"): return 1
    if t in ("+","*"):
        a = expr.get("a") or []
        return 1 + sum(_rw_nodes(x) for x in a)
    return 1

def _rw_canon_key(expr):
    t = expr.get("t")
    if t=="c": return f"c:{int(expr.get('v',0))}"
    if t=="v": return f"v:{expr.get('n','')}"
    if t in ("+","*"):
        ks = [_rw_canon_key(x) for x in (expr.get("a") or [])]
        ks.sort()
        return f"{t}(" + ",".join(ks) + ")"
    return "?"

def _rw_apply_local_rule(sub, rule):
    t = sub.get("t")

    if rule=="add_flatten" and t=="+":
        outa=[]; changed=False
        for x in (sub.get("a") or []):
            if isinstance(x, dict) and x.get("t")=="+": outa.extend(x.get("a") or []); changed=True
            else: outa.append(x)
        if changed: sub["a"]=outa
        return True if changed else False

    if rule=="mul_flatten" and t=="*":
        outa=[]; changed=False
        for x in (sub.get("a") or []):
            if isinstance(x, dict) and x.get("t")=="*": outa.extend(x.get("a") or []); changed=True
            else: outa.append(x)
        if changed: sub["a"]=outa
        return True if changed else False

    if rule=="mul_annihilate0" and t=="*":
        for x in (sub.get("a") or []):
            if isinstance(x,dict) and x.get("t")=="c" and int(x.get("v",0))==0:
                return {"t":"c","v":0}
        return False

    if rule=="add_foldconst" and t=="+":
        s=0; outa=[]; seen=False
        for x in (sub.get("a") or []):
            if isinstance(x,dict) and x.get("t")=="c":
                s += int(x.get("v",0)); seen=True
            else:
                outa.append(x)
        if seen: outa.append({"t":"c","v":s})
        sub["a"]=outa
        return True if seen else False

    if rule=="mul_foldconst" and t=="*":
        prod=1; outa=[]; seen=False
        for x in (sub.get("a") or []):
            if isinstance(x,dict) and x.get("t")=="c":
                prod *= int(x.get("v",1)); seen=True
            else:
                outa.append(x)
        if seen: outa.append({"t":"c","v":prod})
        sub["a"]=outa
        return True if seen else False

    if rule=="add_drop0" and t=="+":
        a = [x for x in (sub.get("a") or []) if not (isinstance(x,dict) and x.get("t")=="c" and int(x.get("v",0))==0)]
        if len(a)==0: return {"t":"c","v":0}
        if len(a)==1: return a[0]
        sub["a"]=a
        return True

    if rule=="mul_drop1" and t=="*":
        a = [x for x in (sub.get("a") or []) if not (isinstance(x,dict) and x.get("t")=="c" and int(x.get("v",1))==1)]
        if len(a)==0: return {"t":"c","v":1}
        if len(a)==1: return a[0]
        sub["a"]=a
        return True

    if rule=="distribute_left" and t=="*":
        a = sub.get("a") or []
        if len(a)!=2: return False
        A,B = a[0],a[1]
        if isinstance(B,dict) and B.get("t")=="+":
            terms=B.get("a") or []
            return {"t":"+","a":[{"t":"*","a":[A, t]} for t in terms]}
        return False

    if rule=="distribute_right" and t=="*":
        a = sub.get("a") or []
        if len(a)!=2: return False
        B,A = a[0],a[1]
        if isinstance(B,dict) and B.get("t")=="+":
            terms=B.get("a") or []
            return {"t":"+","a":[{"t":"*","a":[t, A]} for t in terms]}
        return False

    if rule=="add_sort" and t=="+":
        a = sub.get("a") or []
        before=[_rw_canon_key(x) for x in a]
        a.sort(key=_rw_canon_key)
        after=[_rw_canon_key(x) for x in a]
        sub["a"]=a
        return True if before!=after else False

    if rule=="mul_sort" and t=="*":
        a = sub.get("a") or []
        before=[_rw_canon_key(x) for x in a]
        a.sort(key=_rw_canon_key)
        after=[_rw_canon_key(x) for x in a]
        sub["a"]=a
        return True if before!=after else False

    return False

def _rw_get_at(expr, path):
    cur = expr
    for i in path:
        a = cur.get("a") or []
        if int(i) < 0 or int(i) >= len(a): return None
        cur = a[int(i)]
    return cur

def _rw_set_at(expr, path, new_sub):
    if not path: return new_sub
    cur = expr
    for i in path[:-1]:
        a = cur.get("a") or []
        cur = a[int(i)]
    a = cur.get("a") or []
    a[int(path[-1])] = new_sub
    cur["a"] = a
    return expr

def _rw_normalize_one_pass(expr, path, max_nodes, rules):
    # post-order traversal, stop at first change
    t = expr.get("t")
    if t in ("+","*"):
        a = expr.get("a") or []
        for i in range(len(a)):
            path.append(i)
            changed = _rw_normalize_one_pass(a[i], path, max_nodes, rules)
            path.pop()
            if changed: return True
            if _rw_nodes(expr) > max_nodes: return False

    for r in rules:
        sub = _rw_get_at(expr, path)
        if sub is None or not isinstance(sub, dict): return False
        before = dict(sub)  # shallow; ok because we only use for revert on explode
        applied = _rw_apply_local_rule(sub, r)
        if applied is False:
            continue
        if isinstance(applied, dict):
            expr = _rw_set_at(expr, path, applied)
        if _rw_nodes(expr) > max_nodes:
            # revert best-effort (path-local)
            expr = _rw_set_at(expr, path, before)
            return False
        return True
    return False

def _rw_normalize(expr, max_steps, max_nodes):
    rules = ["add_flatten","mul_flatten","mul_annihilate0","add_foldconst","mul_foldconst","add_drop0","mul_drop1",
             "distribute_left","distribute_right","add_sort","mul_sort"]
    cur = expr
    for _ in range(max_steps):
        path=[]
        if _rw_nodes(cur) > max_nodes: break
        changed = _rw_normalize_one_pass(cur, path, max_nodes, rules)
        if not changed: break
    return cur

def _make_rw_eq_job_v1(seed_hex=None) -> dict:
    # seeded random start; goal = deterministic normalize(start)
    if seed_hex is None:
        seed_hex = hashlib.sha256(os.urandom(32)).hexdigest()
    seed = int(seed_hex[:16], 16)
    rng = random.Random(seed)

    vars_ = ["x","y","z"]
    def rv():
        return {"t":"v","n": rng.choice(vars_)}
    def rc():
        return {"t":"c","v": rng.choice([0,1,2,3,-1])}
    def rsum(k):
        return {"t":"+","a":[rv() if rng.random()<0.7 else rc() for _ in range(k)]}
    def rprod(k):
        return {"t":"*","a":[rv() if rng.random()<0.7 else rc() for _ in range(k)]}

    # start: (* (sum2) (sum2)) or (* (prod2) (sum3)) etc
    if rng.random() < 0.6:
        start = {"t":"*","a":[rsum(rng.choice([2,3])), rsum(rng.choice([2,3]))]}
    else:
        start = {"t":"*","a":[rprod(2), rsum(3)]}

    max_steps = 600
    max_nodes  = 6000
    goal = _rw_normalize(start, max_steps, max_nodes)
    return {"kind":"rw_eq_v1","theory":"ring_lite_v1","start":start,"goal":goal,"max_steps":max_steps,"max_nodes":max_nodes, "seed_hex": seed_hex}
