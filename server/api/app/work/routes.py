import os, json, uuid, hashlib, datetime
from fastapi import APIRouter, HTTPException
from sqlalchemy.orm import Session
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
def submit_job(device_id: str, lease_id: str, job_id: str, output: dict):
    """
    Validate output; if accepted, mint signed work_receipt (server-signed) and write into ledger.
    Credits = job.credits if accepted else 0.
    """
    db: Session = SessionWork()
    try:
        lease = db.query(JobLease).filter(and_(JobLease.lease_id==lease_id, JobLease.job_id==job_id, JobLease.device_id==device_id, JobLease.active==True)).first()
        if not lease:
            raise HTTPException(status_code=400, detail="invalid_lease")
        if lease.expires_at < _now():
            lease.active = False
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
            payload_obj = {
                "type": "work_receipt",
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
def device_register(device_id: str, platform: str = "unknown", has_lean: bool = False, ram_mb: int = 0, disk_mb: int = 0, topics: str = "", meta: dict | None = None):
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
        d.topics_csv = _csv_norm(topics)
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
