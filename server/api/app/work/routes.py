import os, json, uuid, hashlib, datetime
from fastapi import APIRouter, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import and_
from .db.work_db import SessionWork
from .db.models import Job, JobLease, WorkResult

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

def _validator_for(kind: str):
    if kind == "toy_math":
        return validate_toy_math
    if kind == "lean_check":
        return validate_lean_check
    return None

@router.post("/jobs/create")
def create_job(kind: str, payload: dict, credits: int = 1):
    db: Session = SessionWork()
    try:
        jid = str(uuid.uuid4())
        j = Job(job_id=jid, kind=kind, payload_json=_canon(payload), credits=int(credits), status="open")
        db.add(j); db.commit()
        return {"ok": True, "job_id": jid}
    finally:
        db.close()

@router.get("/jobs/pull")
def pull_job(device_id: str):
    """
    Lease one open job. If none, returns ok=true + job=null.
    """
    db: Session = SessionWork()
    try:
        # find open job
        j = db.query(Job).filter(Job.status == "open").order_by(Job.created_at.asc()).first()
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

        awarded = int(job.credits) if ok else 0

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
            wr.receipt_id = payload_obj["receipt_id"]
            db.add(wr); db.commit()
            return {"ok": True, "accepted": True, "reason": reason, "awarded_credits": awarded, "receipt": env}

        return {"ok": True, "accepted": False, "reason": reason, "awarded_credits": 0}
    finally:
        db.close()
