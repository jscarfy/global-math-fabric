from fastapi import FastAPI, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
import base64, hashlib, json, zipfile, io, uuid, secrets

from app.db.session import get_db, engine
from app.models import Base
from app.models.task import TaskDef, TaskInstance, Result
from app.models.client import Client, CreditEvent
from app.models.receipt import Receipt
from app.models.replay import ReplayCheck
from app.schemas.task import (
    EnqueueResponse,
    CreateInstancesRequest, CreateInstancesResponse,
    LeaseRequest, LeaseResponse,
    ReportRequest, ReportResponse
)
from app.schemas.auth import RegisterRequest, RegisterResponse
from app.schemas.credits import MeResponse, LeaderboardResponse, LeaderboardRow
from app.schemas.receipt import ReceiptsResponse, ReceiptRow
from app.schemas.replay import ReplayQueueResponse, ReplayQueueItem, ReplayReportRequest, ReplayReportResponse
from app.security.signing import load_truststore, verify_bundle_ed25519
from app.security.receipt_signing import sign_receipt

app = FastAPI(title="Global Math Fabric API")

@app.on_event("startup")
def _startup():
    Base.metadata.create_all(bind=engine)

@app.get("/health")
def health():
    return {"ok": True}

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_json(v: dict) -> str:
    return sha256_hex(json.dumps(v, sort_keys=True).encode("utf-8"))

def require_client(db: Session, x_api_key: str | None) -> Client:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    api_key_hash = sha256_hex(x_api_key.encode("utf-8"))
    c = db.query(Client).filter(Client.api_key_hash == api_key_hash, Client.is_active == True).first()
    if not c:
        raise HTTPException(status_code=401, detail="invalid_api_key")
    return c

def award(db: Session, client: Client, kind: str, points: int, meta: dict):
    ev = CreditEvent(client_id_fk=client.id, kind=kind, points=points, meta=meta)
    client.credits_total = (client.credits_total or 0) + points
    db.add(ev)
    db.add(client)
    db.commit()

@app.post("/auth/register", response_model=RegisterResponse)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    # if client_id exists, refuse (simple policy)
    exists = db.query(Client).filter(Client.client_id == req.client_id).first()
    if exists:
        raise HTTPException(status_code=409, detail="client_id_taken")

    api_key = secrets.token_urlsafe(32)
    c = Client(
        client_id=req.client_id,
        api_key_hash=sha256_hex(api_key.encode("utf-8")),
        display_name=req.display_name,
        is_active=True,
        credits_total=0,
    )
    db.add(c)
    db.commit()
    return RegisterResponse(client_id=req.client_id, api_key=api_key)

@app.get("/credits/me", response_model=MeResponse)
def credits_me(x_api_key: str | None = Header(default=None, alias="X-API-Key"), db: Session = Depends(get_db)):
    c = require_client(db, x_api_key)
    return MeResponse(client_id=c.client_id, display_name=c.display_name, credits_total=c.credits_total or 0)

@app.get("/credits/leaderboard", response_model=LeaderboardResponse)
def credits_leaderboard(limit: int = 20, db: Session = Depends(get_db)):
    rows = (
        db.query(Client)
        .filter(Client.is_active == True)
        .order_by(Client.credits_total.desc(), Client.created_at.asc())
        .limit(max(1, min(limit, 200)))
        .all()
    )
    return LeaderboardResponse(rows=[
        LeaderboardRow(client_id=r.client_id, display_name=r.display_name, credits_total=r.credits_total or 0)
        for r in rows
    ])

@app.post("/tasks/enqueue", response_model=EnqueueResponse)
def enqueue_task(bundle_b64: str, db: Session = Depends(get_db)):
    """
    Admin endpoint (MVP): base64 of bundle.zip containing manifest.json + module.wasm
    """
    try:
        bundle = base64.b64decode(bundle_b64)
        zf = zipfile.ZipFile(io.BytesIO(bundle))
        manifest_raw = zf.read("manifest.json")
        wasm_bytes = zf.read("module.wasm")
        sig_raw = zf.read("signature.json")
        sig_doc = json.loads(sig_raw.decode("utf-8"))
        manifest = json.loads(manifest_raw.decode("utf-8"))
        name = manifest.get("name", "unnamed-task")

        trust = load_truststore("trust/public_keys.json")
        verify_bundle_ed25519(manifest_raw, wasm_bytes, sig_doc, trust)
        manifest["_sig"] = sig_doc
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid bundle: {e}")

    t = TaskDef(
        name=name,
        manifest=manifest,
        wasm_bytes=wasm_bytes,
        wasm_sha256=sha256_hex(wasm_bytes),
        is_active=True,
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return EnqueueResponse(task_id=str(t.id))

@app.post("/instances/create", response_model=CreateInstancesResponse)
def create_instances(req: CreateInstancesRequest, db: Session = Depends(get_db)):
    task = db.query(TaskDef).filter(TaskDef.id == req.task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="task_not_found")
    if not task.is_active:
        raise HTTPException(status_code=400, detail="task_inactive")

    ids = []
    for inp in req.inputs:
        inst = TaskInstance(
            task_id=task.id,
            input_json=inp,
            priority=req.priority,
            status="pending",
            verified=False,
            verification_target=2,
        )
        db.add(inst)
        db.flush()
        ids.append(str(inst.id))
    db.commit()
    return CreateInstancesResponse(instance_ids=ids)

@app.post("/instances/lease", response_model=LeaseResponse)
def lease_instance(
    req: LeaseRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db)
):
    client = require_client(db, x_api_key)
    # Enforce that request client_id matches authenticated client_id (prevents spoofing)
    if req.client_id != client.client_id:
        raise HTTPException(status_code=401, detail="client_id_mismatch")

    now = datetime.now(timezone.utc)

    require_mobile_ok = bool(getattr(req, "mobile", False))
    require_mobile_abi = require_mobile_ok  # mobile implies abi gating

    q = (
        db.query(TaskInstance)
        .join(TaskDef, TaskDef.id == TaskInstance.task_id)
        .filter(TaskDef.is_active == True)
        .filter(TaskInstance.verified == False)
        .filter(TaskInstance.status.in_(["pending", "leased"]))
        .filter((TaskInstance.lease_expires_at.is_(None)) | (TaskInstance.lease_expires_at < now))
    )

    if require_mobile_ok:
        q = q.filter(TaskDef.manifest["mobile_ok"].as_boolean() == True)

    if require_mobile_abi:
        q = q.filter(TaskDef.manifest["abi"].as_string() == "gmf-abi-1")

    inst = q.order_by(TaskInstance.priority.desc(), TaskInstance.created_at.asc()).first()

    if not inst:
        return LeaseResponse(note="no_instance_available")

    token = uuid.uuid4().hex
    inst.leased_by = client.client_id
    inst.lease_token = token
    inst.lease_expires_at = now + timedelta(seconds=req.lease_seconds)
    inst.status = "leased"
    inst.attempts = (inst.attempts or 0) + 1

    db.add(inst)
    db.commit()
    db.refresh(inst)

    task = db.query(TaskDef).filter(TaskDef.id == inst.task_id).first()
    if not task:
        raise HTTPException(status_code=500, detail="task_def_missing")

    wasm_b64 = base64.b64encode(task.wasm_bytes).decode("ascii")
    return LeaseResponse(
        instance_id=str(inst.id),
        task_id=str(task.id),
        manifest=task.manifest,
        wasm_b64=wasm_b64,
        input_json=inst.input_json,
        lease_token=token,
        lease_expires_at=inst.lease_expires_at,
        note="leased",
    )


@app.post("/instances/report", response_model=ReportResponse)
def report_instance(
    req: ReportRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db)
):
    client = require_client(db, x_api_key)
    if req.client_id != client.client_id:
        raise HTTPException(status_code=401, detail="client_id_mismatch")

    now = datetime.now(timezone.utc)
    inst = db.query(TaskInstance).filter(TaskInstance.id == req.instance_id).first()
    if not inst:
        raise HTTPException(status_code=404, detail="instance_not_found")

    if inst.lease_token != req.lease_token:
        return ReportResponse(accepted=False, verified_now=False, note="bad_lease_token")
    if inst.leased_by != client.client_id:
        return ReportResponse(accepted=False, verified_now=False, note="client_mismatch")
    if inst.lease_expires_at is None or inst.lease_expires_at < now:
        return ReportResponse(accepted=False, verified_now=False, note="lease_expired")
    if inst.verified:
        return ReportResponse(accepted=False, verified_now=True, note="already_verified")

    out_sha = sha256_json(req.stdout_json)
    r = Result(
        instance_id=inst.id,
        client_id=client.client_id,
        stdout_json=req.stdout_json,
        stdout_sha256=out_sha,
        stderr_text=req.stderr_text,
    )
    try:
        db.add(r)
        db.commit()
    except Exception:
        db.rollback()
        return ReportResponse(accepted=False, verified_now=False, note="duplicate_or_error")

    # Credits for accepted report
    award(db, client, "report_accepted", 1, {"instance_id": req.instance_id})

    # Verification: N matching output hashes
    rows = db.query(Result.stdout_sha256, Result.client_id).filter(Result.instance_id == inst.id).all()
    counts = {}
    clients_by_hash = {}
    for h, cid in rows:
        counts[h] = counts.get(h, 0) + 1
        clients_by_hash.setdefault(h, set()).add(cid)

    winning_hash = None
    for h, n in counts.items():
        if n >= inst.verification_target:
            winning_hash = h
            break

    verified_now = winning_hash is not None
    if verified_now:
        inst.verified = True
        inst.status = "verified"
        inst.lease_token = None
        inst.leased_by = None
        inst.lease_expires_at = None
        db.add(inst)
        db.commit()

        # Bonus credits to clients whose outputs match the winning hash
        winners = list(clients_by_hash.get(winning_hash, []))
        for winner_client_id in winners:
            # Emit signed receipt for auditability
            body = {
                "kind": "instance_verified",
                "instance_id": str(inst.id),
                "stdout_sha256": winning_hash,
                "points": 5,
                "ts": datetime.utcnow().isoformat() + 'Z',
                "client_id": winner_client_id,
            }
            rk, sigb64 = sign_receipt(body)

            wc = db.query(Client).filter(Client.client_id == winner_client_id).first()
            if wc:
                award(db, wc, "instance_verified", 5, {"instance_id": req.instance_id, "stdout_sha256": winning_hash})
                db.add(Receipt(instance_id_fk=inst.id, issued_to_client_id=winner_client_id, credits_delta=5, body=body, sig_key_id=rk, signature_b64=sigb64))
                db.commit()

    return ReportResponse(accepted=True, verified_now=verified_now, note="ok")


@app.get("/receipts/me", response_model=ReceiptsResponse)
def receipts_me(
    limit: int = 50,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db)
):
    c = require_client(db, x_api_key)
    rows = (
        db.query(Receipt)
        .filter(Receipt.issued_to_client_id == c.client_id)
        .order_by(Receipt.created_at.desc())
        .limit(max(1, min(limit, 500)))
        .all()
    )
    return ReceiptsResponse(receipts=[
        ReceiptRow(
            instance_id=str(r.instance_id_fk),
            credits_delta=r.credits_delta,
            body=r.body,
            sig_key_id=r.sig_key_id,
            signature_b64=r.signature_b64,
            created_at=r.created_at.isoformat()
        ) for r in rows
    ])

@app.get("/receipts/instance/{instance_id}", response_model=ReceiptsResponse)
def receipts_for_instance(
    instance_id: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db)
):
    c = require_client(db, x_api_key)
    rows = (
        db.query(Receipt)
        .filter(Receipt.instance_id_fk == instance_id)
        .filter(Receipt.issued_to_client_id == c.client_id)
        .order_by(Receipt.created_at.desc())
        .all()
    )
    return ReceiptsResponse(receipts=[
        ReceiptRow(
            instance_id=str(r.instance_id_fk),
            credits_delta=r.credits_delta,
            body=r.body,
            sig_key_id=r.sig_key_id,
            signature_b64=r.signature_b64,
            created_at=r.created_at.isoformat()
        ) for r in rows
    ])


@app.get("/replay/queue", response_model=ReplayQueueResponse)
def replay_queue(limit: int = 200, db: Session = Depends(get_db)):
    """
    Returns ONE verified instance that has not yet been replay-checked.
    MVP: no auth; in production restrict to verifier keys.
    """
    # find a verified instance without replay_checks
    inst = (
        db.query(TaskInstance)
        .filter(TaskInstance.verified == True)
        .order_by(TaskInstance.created_at.desc())
        .limit(max(1, min(limit, 1000)))
        .all()
    )
    for i in inst:
        exists = db.query(ReplayCheck).filter(ReplayCheck.instance_id_fk == i.id).first()
        if exists:
            continue
        task = db.query(TaskDef).filter(TaskDef.id == i.task_id).first()
        if not task:
            continue
        # compute winning hash from results (majority)
        rows = db.query(Result.stdout_sha256).filter(Result.instance_id == i.id).all()
        counts = {}
        for (h,) in rows:
            counts[h] = counts.get(h, 0) + 1
        winning = None
        for h, n in counts.items():
            if n >= i.verification_target:
                winning = h
                break
        if not winning:
            continue
        wasm_b64 = base64.b64encode(task.wasm_bytes).decode("ascii")
        return ReplayQueueResponse(
            item=ReplayQueueItem(
                instance_id=str(i.id),
                manifest=task.manifest,
                wasm_b64=wasm_b64,
                input_json=i.input_json,
                winning_sha256=winning
            ),
            note="ok"
        )
    return ReplayQueueResponse(item=None, note="no_item")

@app.post("/replay/report", response_model=ReplayReportResponse)
def replay_report(req: ReplayReportRequest, db: Session = Depends(get_db)):
    inst = db.query(TaskInstance).filter(TaskInstance.id == req.instance_id).first()
    if not inst:
        return ReplayReportResponse(accepted=False, note="instance_not_found")
    exists = db.query(ReplayCheck).filter(ReplayCheck.instance_id_fk == inst.id).first()
    if exists:
        return ReplayReportResponse(accepted=False, note="already_checked")

    db.add(ReplayCheck(instance_id_fk=inst.id, ok=req.ok, verifier_id=req.verifier_id, meta=req.detail))
    db.commit()

    # MVP: if mismatch, mark disputed
    if not req.ok:
        inst.status = "disputed"
        db.add(inst)
        db.commit()
    return ReplayReportResponse(accepted=True, note="ok")
