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
from app.models.device import Device, DeviceChallenge, Heartbeat
from app.schemas.task import (
    EnqueueResponse,
    CreateInstancesRequest, CreateInstancesResponse,
    LeaseRequest, LeaseResponse,
    ReportRequest, ReportResponse
)
from app.schemas.auth import RegisterRequest, RegisterResponse
from app.schemas.credits import MeResponse, LeaderboardResponse, LeaderboardRow
from app.schemas.receipt import ReceiptsResponse, ReceiptRow
from app.schemas.device import DeviceRegisterRequest, DeviceRegisterResponse, DeviceChallengeResponse, HeartbeatRequest, HeartbeatResponse
from app.schemas.attest import DeviceAttestRequest, DeviceAttestResponse
from app.crypto.receipt import sign_receipt, now_iso
from app.crypto.governance import load_governance_or_die
from app.crypto import ledger as ledger_mod
from app.crypto import checkpointing
from app.work.routes import router as work_router
from app.devices.routes import router as devices_router
from app.credits import router as credits_router
from app.enroll import router as enroll_router
from app.policy import router as policy_router
from app.verification import router as verification_router
from app.crypto import amendments
from app.crypto import merkle as merkle_mod
from app.schemas.receipt import ReceiptEnvelope
from app.schemas.replay import ReplayQueueResponse, ReplayQueueItem, ReplayReportRequest, ReplayReportResponse
from app.security.signing import load_truststore, verify_bundle_ed25519
from app.security.receipt_signing import sign_receipt
from app.security.device_auth import verify_ed25519_signature
from app.security.risk import decay_risk, fingerprint_hash, result_weight_from_risk, reward_mult_from_risk, _geti

app = FastAPI(title="Global Math Fabric API")

# ---- Governance (fail-fast) ----
GMF_GOV = load_governance_or_die()
# -------------------------------

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

def require_client(db: Session, x_api_key: str | None, request: Request | None = None, device_id: str | None = None) -> Client:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    api_key_hash = sha256_hex(x_api_key.encode("utf-8"))
    c = db.query(Client).filter(Client.api_key_hash == api_key_hash, Client.is_active == True).first()
    if not c:
        raise HTTPException(status_code=401, detail="invalid_api_key")
    
    # --- risk decay + fingerprint update (privacy-minimal) ---
    now = datetime.now(timezone.utc)
    c.risk_score = decay_risk(float(getattr(c, "risk_score", 0.0)), getattr(c, "risk_updated_at", None), now)
    c.risk_updated_at = now
    c.last_seen_at = now

    ua = None
    ip = None
    if request is not None:
        ua = request.headers.get("User-Agent")
        # best-effort client ip
        ip = getattr(request.client, "host", None) if getattr(request, "client", None) else None

    # optional device_id passed explicitly (future: from client payload)
    if device_id:
        c.device_id = device_id

    fp = fingerprint_hash(ua, c.device_id, ip)
    c.fingerprint_hash = fp

    # sybil-ish penalty: many clients share same fingerprint
    shared = db.query(Client).filter(Client.fingerprint_hash == fp).count()
    penalty = _geti("GMF_RISK_PENALTY_SHARED_FINGERPRINT", 8)
    if shared >= 3:
        # each extra beyond 2 adds penalty/2 (gentle)
        c.risk_score += float((shared - 2) * max(1, penalty // 2))
        c.risk_updated_at = now

    db.add(c)
    db.commit()

return c

def require_verifier(x_verifier_key: str | None):
    expected = os.environ.get("GMF_VERIFIER_SHARED_KEY", "")
    if not expected:
        raise HTTPException(status_code=500, detail="verifier_key_not_configured")
    if not x_verifier_key or x_verifier_key != expected:
        raise HTTPException(status_code=401, detail="unauthorized_verifier")


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
    c = require_client(db, x_api_key, request=request)
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

    
    # Prefer heavy tasks when allowed (otherwise we filtered them out already)
    if heavy_allowed:
        q = q.order_by(
            (TaskDef.manifest["power_profile"].as_string() == "heavy").desc(),
            TaskInstance.created_at.asc()
        )
    else:
        q = q.order_by(TaskInstance.created_at.asc())

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
        
    # --- heavy work proof audit (sampled) ---
    try:
        audit_rate = float(os.environ.get("GMF_HEAVY_PROOF_AUDIT_RATE", "0.01"))
        max_verify = int(os.environ.get("GMF_HEAVY_PROOF_MAX_ITERS_VERIFY", "2000000"))
        if random.random() < audit_rate:
            # Load task manifest for this instance
            td = db.query(TaskDef).filter(TaskDef.id == inst.task_id_fk).first() if hasattr(inst, "task_id_fk") else None
            manifest = td.manifest if td else None
            if manifest and manifest.get("power_profile") == "heavy":
                wp = (req.stdout_json or {}).get("_work_proof", None)
                if wp and isinstance(wp, dict):
                    kind = wp.get("kind")
                    payload = wp.get("payload") or {}
                    # Only verify bounded-cost proofs to avoid server DoS
                    if kind == "sha256_chain":
                        iters = int(payload.get("iters", 0) or 0)
                        if 0 < iters <= max_verify:
                            import hashlib, json
                            def canon(v):
                                if isinstance(v, dict):
                                    return {k: canon(v[k]) for k in sorted(v.keys())}
                                if isinstance(v, list):
                                    return [canon(x) for x in v]
                                return v
                            msg = {"instance_id": req.instance_id, "stdout_sha256": req.stdout_sha256}
                            state = hashlib.sha256((req.instance_id + "|" + req.stdout_sha256).encode("utf-8")).digest()
                            for _ in range(iters):
                                state = hashlib.sha256(state).digest()
                            digest = state.hex()
                            if digest != str(payload.get("digest", "")):
                                raise HTTPException(status_code=400, detail="heavy_proof_audit_failed_sha256_chain")
                    elif kind == "poly_mod":
                        iters = int(payload.get("iters", 0) or 0)
                        if 0 < iters <= max_verify:
                            import hashlib
                            p_mod = int(payload.get("mod_p", 1000000007) or 1000000007)
                            a = int(payload.get("a", 48271) or 48271) % p_mod
                            b = int(payload.get("b", 0) or 0) % p_mod
                            x0 = int(payload.get("x0", 1) or 1) % p_mod

                            seed = hashlib.sha256((req.instance_id + "|" + req.stdout_sha256).encode("utf-8")).digest()
                            seed_u64 = 0
                            for i in range(8):
                                seed_u64 = (seed_u64 << 8) | seed[i]
                            x = x0
                            for _ in range(iters):
                                x = (a * x + b + (seed_u64 % p_mod)) % p_mod

                            h = hashlib.sha256()
                            h.update(req.instance_id.encode("utf-8"))
                            h.update(b"|")
                            h.update(req.stdout_sha256.encode("utf-8"))
                            h.update(b"|")
                            h.update(x.to_bytes(8, "big"))
                            digest = h.hexdigest()
                            if digest != str(payload.get("digest", "")):
                                raise HTTPException(status_code=400, detail="heavy_proof_audit_failed_poly_mod")
    except HTTPException:
        raise
    except Exception:
        # audit failures other than explicit mismatch should not break normal flow in MVP
        pass
    # ----------------------------------------

    
    # --- issue receipt (offline verifiable) ---
    manifest = {}
    try:
        td2 = db.query(TaskDef).filter(TaskDef.id == getattr(inst, 'task_id_fk', None)).first()
        manifest = td2.manifest if td2 else {}
    except Exception:
        manifest = {}
    receipt_payload = {
        "v": 1,
        "issued_at": now_iso(),
        "client_id": str(c.id),
        "device_id": str(getattr(inst, "leased_device_id_fk", "") or getattr(inst, "device_id_fk", "") or ""),
        "task_id": str(getattr(inst, "task_id_fk", "")),
        "instance_id": str(req.instance_id),
        "awarded_credits": int(getattr(inst, "credits_awarded", 0) or 0),
        "risk_score": float(getattr(c, "risk_score", 0.0) or 0.0),
        "stdout_sha256": str(req.stdout_sha256),
        # optional proof summary (client/server already computed)
        "work_proof": (req.stdout_json or {}).get("_work_proof", None),
        "task_manifest_hash": (hashlib.sha256(
            json.dumps((manifest if isinstance(manifest, dict) else {}), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()),
        "pricing_breakdown": (getattr(inst, "pricing_breakdown", None) or {}),
    }
        # deterministic receipt_id for indexing
    receipt_payload["receipt_id"] = hashlib.sha256(
        json.dumps(receipt_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    key_id, sig_b64, payload_b64 = sign_receipt(receipt_payload)
    receipt_env = ReceiptEnvelope(key_id=key_id, payload_b64=payload_b64, signature_b64=sig_b64)
    # -----------------------------------------

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
        base_points = 5
        for winner_client_id in winners:
            # Emit signed receipt for auditability
            body = {
                "kind": "instance_verified",
                "instance_id": str(inst.id),
                "stdout_sha256": winning_hash,
                "points": int(points),
                "ts": datetime.utcnow().isoformat() + 'Z',
                "client_id": winner_client_id,
            }
            rk, sigb64 = sign_receipt(body)

            wc = db.query(Client).filter(Client.client_id == winner_client_id).first()
            if wc:
                rmult = reward_mult_from_risk(float(getattr(wc,'risk_score',0.0)))
                points = max(1, int(round(base_points * rmult)))
                award(db, wc, "instance_verified", points, {"instance_id": req.instance_id, "stdout_sha256": winning_hash, "rmult": rmult})
                db.add(Receipt(instance_id_fk=inst.id, issued_to_client_id=winner_client_id, credits_delta=int(points), body=body, sig_key_id=rk, signature_b64=sigb64))
                db.commit()

    return ReportResponse(accepted=True, verified_now=verified_now, note="ok")


@app.get("/receipts/me", response_model=ReceiptsResponse)
def receipts_me(
    limit: int = 50,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db)
):
    c = require_client(db, x_api_key, request=request)
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
    c = require_client(db, x_api_key, request=request)
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
def replay_queue(limit: int = 200, x_verifier_key: str | None = Header(default=None, alias="X-Verifier-Key"), db: Session = Depends(get_db)):
    """
    Returns ONE verified instance that has not yet been replay-checked.
    Auth: requires X-Verifier-Key.
    """
    require_verifier(x_verifier_key)
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
def replay_report(req: ReplayReportRequest, x_verifier_key: str | None = Header(default=None, alias="X-Verifier-Key"), db: Session = Depends(get_db)):
    inst = db.query(TaskInstance).filter(TaskInstance.id == req.instance_id).first()
    if not inst:
        return ReplayReportResponse(accepted=False, note="instance_not_found")
    exists = db.query(ReplayCheck).filter(ReplayCheck.instance_id_fk == inst.id).first()
    if exists:
        return ReplayReportResponse(accepted=False, note="already_checked")

    db.add(ReplayCheck(instance_id_fk=inst.id, ok=req.ok, verifier_id=req.verifier_id, meta=req.detail))
    db.commit()

    # If mismatch, mark disputed + clawback
    if not req.ok:
        inst.status = "disputed"
        db.add(inst)
        db.commit()

        # Claw back credits previously issued for this instance (MVP: based on receipts)
        recs = db.query(Receipt).filter(Receipt.instance_id_fk == inst.id).all()
        for r in recs:
            wc = db.query(Client).filter(Client.client_id == r.issued_to_client_id).first()
            if wc:
                # negative credit event
                db.add(CreditEvent(client_id=wc.id, kind="replay_clawback", delta=-int(r.credits_delta), meta={"instance_id": str(inst.id)}))
                wc.credits_total = int(wc.credits_total) - int(r.credits_delta)
                db.add(wc)
                # signed clawback receipt
                body = {
                    "kind": "replay_clawback",
                    "instance_id": str(inst.id),
                    "points": -int(r.credits_delta),
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "client_id": r.issued_to_client_id,
                }
                rk, sigb64 = sign_receipt(body)
                db.add(Receipt(instance_id_fk=inst.id, issued_to_client_id=r.issued_to_client_id, credits_delta=-int(r.credits_delta), body=body, sig_key_id=rk, signature_b64=sigb64))
        db.commit()
    return ReplayReportResponse(accepted=True, note="ok")


def attrib_mismatch_clients(db: Session, inst: TaskInstance) -> list[Client]:
    # determine current "winning" hash under weighted rule (what the network accepted)
    rows = db.query(Result).filter(Result.instance_id == inst.id).all()
    weight_sums = {}
    for row in rows:
        w = float(getattr(row, "weight", 1.0) or 1.0)
        weight_sums[row.stdout_sha256] = weight_sums.get(row.stdout_sha256, 0.0) + w
    winning = None
    for h, wsum in weight_sums.items():
        if wsum >= float(inst.verification_target):
            winning = h
            break
    if not winning:
        return []
    client_ids = [r.client_id for r in rows if r.stdout_sha256 == winning]
    if not client_ids:
        return []
    return db.query(Client).filter(Client.id.in_(client_ids)).all()


@app.post("/devices/register", response_model=DeviceRegisterResponse)
def device_register(
    req: DeviceRegisterRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    request: Request = None,
    db: Session = Depends(get_db)
):
    c = require_client(db, x_api_key, request=request)
    # Upsert by pubkey
    d = db.query(Device).filter(Device.pubkey_b64 == req.pubkey_b64).first()
    if d:
        if str(d.client_id_fk) != str(c.id):
            # same pubkey used by different client => reject (identity collision)
            raise HTTPException(status_code=409, detail="pubkey_already_registered_to_other_client")
        d.label = req.label or d.label
        d.platform = req.platform or d.platform
        d.last_seen_at = datetime.utcnow()
        db.add(d); db.commit()
        return DeviceRegisterResponse(device_id=str(d.id), note="already_registered")
    d = Device(client_id_fk=c.id, pubkey_b64=req.pubkey_b64, label=req.label, platform=req.platform)
    db.add(d); db.commit()
    return DeviceRegisterResponse(device_id=str(d.id), note="ok")

@app.get("/devices/{device_id}/challenge", response_model=DeviceChallengeResponse)
def device_challenge(
    device_id: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    request: Request = None,
    db: Session = Depends(get_db)
):
    c = require_client(db, x_api_key, request=request)
    d = db.query(Device).filter(Device.id == device_id).first()
    if not d or str(d.client_id_fk) != str(c.id) or d.is_revoked:
        raise HTTPException(status_code=404, detail="device_not_found")
    nonce = secrets.token_urlsafe(32)
    db.add(DeviceChallenge(device_id_fk=d.id, nonce=nonce))
    db.commit()
    return DeviceChallengeResponse(device_id=str(d.id), nonce=nonce, note="ok")

@app.post("/devices/heartbeat", response_model=HeartbeatResponse)
def device_heartbeat(
    req: HeartbeatRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    request: Request = None,
    db: Session = Depends(get_db)
):
    c = require_client(db, x_api_key, request=request)
    d = db.query(Device).filter(Device.id == req.device_id).first()
    if not d or str(d.client_id_fk) != str(c.id) or d.is_revoked:
        raise HTTPException(status_code=404, detail="device_not_found")
    d.last_seen_at = datetime.utcnow()
    d.last_capabilities = req.payload
    db.add(d)
    db.add(Heartbeat(device_id_fk=d.id, payload=req.payload))
    db.commit()
    return HeartbeatResponse(accepted=True, note="ok")


@app.post("/devices/attest", response_model=DeviceAttestResponse)
def device_attest(
    req: DeviceAttestRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    request: Request = None,
    db: Session = Depends(get_db)
):
    c = require_client(db, x_api_key, request=request)
    d = db.query(Device).filter(Device.id == req.device_id).first()
    if not d or str(d.client_id_fk) != str(c.id) or d.is_revoked:
        raise HTTPException(status_code=404, detail="device_not_found")
    d.attestation_level = req.level
    d.attestation_doc = req.doc
    d.attested_at = datetime.utcnow()
    d.last_seen_at = datetime.utcnow()
    db.add(d)
    db.commit()
    return DeviceAttestResponse(accepted=True, note="ok")


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except Exception:
        return default

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default

def compute_awarded_credits(manifest: dict, risk_score: float, antifarm_count: int) -> int:
    """
    Pricing model (MVP):
      - base light/heavy
      - heavy_work.kind + iters contribute linearly per 1M iters
      - cap per instance
      - risk penalty: multiplier = max(0, 1 - (risk/100)*penalty_per_100)
      - anti-farm: if antifarm_count > threshold, multiplier decays linearly by decay_per_extra; floored by min_mult
    """
    base_light = _env_int("GMF_CREDITS_BASE_LIGHT", 1)
    base_heavy = _env_int("GMF_CREDITS_BASE_HEAVY", 5)
    cap = _env_int("GMF_CREDITS_MAX_PER_INSTANCE", 200)

    pp = (manifest.get("power_profile") or "light").lower()
    credits = base_heavy if pp == "heavy" else base_light

    # Heavy add-on
    if pp == "heavy":
        hw = manifest.get("heavy_work") or {}
        kind = (hw.get("kind") or "sha256_chain").lower()
        iters = int(hw.get("iters") or 0)
        per_1m = 0.0
        if kind in ("sha256_chain", "sha256"):
            per_1m = _env_float("GMF_CREDITS_RATE_SHA256_PER_1M", 1.0)
        elif kind in ("poly_mod", "polymod"):
            per_1m = _env_float("GMF_CREDITS_RATE_POLYMOD_PER_1M", 1.5)
        else:
            # unknown kind => conservative
            per_1m = _env_float("GMF_CREDITS_RATE_SHA256_PER_1M", 1.0) * 0.5

        credits += int(round((iters / 1_000_000.0) * per_1m))

    # Risk penalty
    pen = _env_float("GMF_RISK_CREDIT_PENALTY_PER_100", 0.5)  # risk=100 => multiply by (1-pen)
    risk_mult = max(0.0, 1.0 - (max(0.0, risk_score) / 100.0) * pen)

    # Anti-farm multiplier
    window_sec = _env_int("GMF_ANTIFARM_WINDOW_SEC", 3600)
    thr = _env_int("GMF_ANTIFARM_THRESHOLD", 50)
    decay = _env_float("GMF_ANTIFARM_DECAY_PER_EXTRA", 0.01)
    min_mult = _env_float("GMF_ANTIFARM_MIN_MULT", 0.2)

    if antifarm_count > thr:
        extra = antifarm_count - thr
        farm_mult = max(min_mult, 1.0 - extra * decay)
    else:
        farm_mult = 1.0

    final = int(math.floor(min(cap, max(0, credits)) * risk_mult * farm_mult))
    return max(0, min(cap, final))


def compute_awarded_credits_and_breakdown(manifest: dict, risk_score: float, antifarm_count: int) -> tuple[int, dict]:
    base_light = _env_int("GMF_CREDITS_BASE_LIGHT", 1)
    base_heavy = _env_int("GMF_CREDITS_BASE_HEAVY", 5)
    cap = _env_int("GMF_CREDITS_MAX_PER_INSTANCE", 200)

    pp = (manifest.get("power_profile") or "light").lower()
    base = base_heavy if pp == "heavy" else base_light

    addon = 0
    kind = None
    iters = 0
    rate_per_1m = 0.0

    if pp == "heavy":
        hw = manifest.get("heavy_work") or {}
        kind = (hw.get("kind") or "sha256_chain").lower()
        iters = int(hw.get("iters") or 0)

        if kind in ("sha256_chain", "sha256"):
            rate_per_1m = _env_float("GMF_CREDITS_RATE_SHA256_PER_1M", 1.0)
        elif kind in ("poly_mod", "polymod"):
            rate_per_1m = _env_float("GMF_CREDITS_RATE_POLYMOD_PER_1M", 1.5)
        else:
            rate_per_1m = _env_float("GMF_CREDITS_RATE_SHA256_PER_1M", 1.0) * 0.5

        addon = int(round((iters / 1_000_000.0) * rate_per_1m))

    raw = base + addon

    # risk penalty
    pen = _env_float("GMF_RISK_CREDIT_PENALTY_PER_100", 0.5)
    risk_mult = max(0.0, 1.0 - (max(0.0, float(risk_score)) / 100.0) * pen)

    # anti-farm
    thr = _env_int("GMF_ANTIFARM_THRESHOLD", 50)
    decay = _env_float("GMF_ANTIFARM_DECAY_PER_EXTRA", 0.01)
    min_mult = _env_float("GMF_ANTIFARM_MIN_MULT", 0.2)

    if int(antifarm_count) > thr:
        extra = int(antifarm_count) - thr
        farm_mult = max(min_mult, 1.0 - extra * decay)
    else:
        farm_mult = 1.0

    capped = min(cap, max(0, raw))
    final = int(math.floor(capped * risk_mult * farm_mult))
    final = max(0, min(cap, final))

    breakdown = {
        "power_profile": pp,
        "base": int(base),
        "addon": int(addon),
        "heavy_kind": kind,
        "heavy_iters": int(iters),
        "rate_per_1m": float(rate_per_1m),
        "raw": int(raw),
        "cap": int(cap),
        "capped": int(capped),
        "risk_score": float(risk_score),
        "risk_penalty_per_100": float(pen),
        "risk_mult": float(risk_mult),
        "antifarm_count": int(antifarm_count),
        "antifarm_threshold": int(thr),
        "antifarm_decay_per_extra": float(decay),
        "antifarm_min_mult": float(min_mult),
        "farm_mult": float(farm_mult),
        "final": int(final),
    }
    return final, breakdown



@app.post("/receipts/verify")
def verify_receipt_endpoint(env: ReceiptEnvelope):
    """
    Verify a receipt envelope and (optionally) return decoded payload for display.
    Uses GMF_RECEIPT_PUBLIC_PEM (default keys/receipt-dev.ed25519.pub.pem).
    """
    pub_pem = os.environ.get("GMF_RECEIPT_PUBLIC_PEM", "keys/receipt-dev.ed25519.pub.pem")
    ok = verify_receipt(env.payload_b64, env.signature_b64, pub_pem)
    payload = None
    if ok:
        try:
            import base64, json as _json, hashlib as _hashlib
            msg = base64.b64decode(env.payload_b64.encode("ascii"))
            payload = _json.loads(msg.decode("utf-8"))
            # optional: recompute receipt_id consistency
            rid = payload.get("receipt_id")
            if rid:
                recomputed = _hashlib.sha256(
                    _json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                ).hexdigest()
                if recomputed != rid:
                    ok = False
        except Exception:
            # keep ok as-is, but no payload
            payload = None
    return {"ok": ok, "key_id": env.key_id, "payload": payload}


@app.get("/governance/rules/current")
def governance_rules_current():
    return {
        "rules_version": GMF_GOV["rules_version"],
        "rules_sha256": GMF_GOV["rules_sha256"],
        "guardian_set_id": GMF_GOV["guardian_set_id"],
        "rules": GMF_GOV["rules"],
        "sigset": GMF_GOV["sigset"],
        "guardian_set": GMF_GOV["guardian_set"],
                "rules_registry_path": GMF_GOV.get("rules_registry_path", "governance/rules/registry.json"),
                "rules_registry": __import__("json").load(open(GMF_GOV.get("rules_registry_path", "governance/rules/registry.json"), "r", encoding="utf-8")),
                "rules_amendments_dir": __import__("os").environ.get("GMF_RULES_AMENDMENTS_DIR", "governance/rules/amendments"),

                "registry": GMF_GOV.get("registry", {}),
                "transitions_dir": "governance/signers/transitions",
                "attestations_dir": "ledger/attestations",

    }

@app.get("/ledger/root")
def ledger_root():
    root, n = ledger_mod.current_root_and_len()
    return {"ledger_root_sha256": root, "entries": n}

@app.get("/ledger/receipts/tail")
def ledger_tail(limit: int = 20):
    return {"limit": int(limit), "lines": ledger_mod.tail(limit)}


@app.get("/ledger/checkpoint/pending")
def ledger_checkpoint_pending(prewarm_budget_nodes: int | None = None):
    """
    Server returns a pending checkpoint request (no signatures).
    Hardening: prewarm Merkle cache (budgeted) before creating pending checkpoint,
    so computing root is stable and won't scan/lag.
    """
    enabled = os.environ.get("GMF_CHECKPOINT_PREWARM_ENABLED", "1") != "0"
    budget = prewarm_budget_nodes
    if budget is None:
        try:
            budget = int(os.environ.get("GMF_CHECKPOINT_PREWARM_BUDGET", "50000"))
        except Exception:
            budget = 50000

    prewarm_res = None
    if enabled:
        try:
            # prewarm internal nodes up to root level for current ledger length
            prewarm_res = ledger_cache_prewarm(budget_nodes=int(budget))
        except Exception:
            prewarm_res = {"ok": False}

    req = checkpointing.create_pending_checkpoint(GMF_GOV["rules_sha256"])
    if prewarm_res is not None:
        req["prewarm"] = prewarm_res
    return req


@app.post("/ledger/checkpoint/submit")
def ledger_checkpoint_submit(checkpoint: dict):
    """
    Accept a threshold-signed checkpoint JSON.
    """
    res = checkpointing.accept_checkpoint(checkpoint, GMF_GOV["rules_sha256"])
    return {"ok": True, **res}

@app.get("/ledger/checkpoints/latest")
def ledger_checkpoints_latest():
    cp = checkpointing.latest_checkpoint()
    return {"ok": bool(cp), "checkpoint": cp}

@app.get("/ledger/receipt/proof")
def ledger_receipt_proof(receipt_id: str):
    """
    Return inclusion proof for receipt envelope identified by receipt_id
    (searching ledger jsonl lines; MVP O(n)).
    Proof is relative to latest checkpoint (if exists), otherwise to current ledger head.
    """
    # load ledger lines
    lines = ledger_mod.tail(2000000000)  # read all (ledger_mod.tail is limited; we need full)
    # fallback: use checkpointing.read_all_lines which returns bytes
    raw_lines = checkpointing.read_all_lines()

    # find the line index containing receipt_id (best-effort string match)
    idx0 = -1
    line_bytes = None
    for i, b in enumerate(raw_lines):
        if receipt_id.encode("utf-8") in b:
            idx0 = i
            line_bytes = b
            break
    if idx0 < 0:
        return {"ok": False, "error": "receipt_id_not_found"}

    # choose anchor: latest checkpoint if it covers this index; else current head
    cp = checkpointing.latest_checkpoint()
    if cp:
        n = int(cp.get("entries") or 0)
        root = str(cp.get("ledger_root_sha256"))
        if idx0 >= n:
            # not yet checkpointed -> use current head
            root, n = checkpointing.current_ledger_root_and_len()
            cp = None
        else:
            # compute proof from first n leaves
            raw_lines = raw_lines[:n]
    else:
        root, n = checkpointing.current_ledger_root_and_len()

    # leaf hashes
    leaf_hashes = [merkle_mod._h(x) for x in raw_lines]
    proof = merkle_mod.build_merkle_proof(leaf_hashes, idx0)

    return {
        "ok": True,
        "receipt_id": receipt_id,
        "index0": idx0,
        "entries": n,
        "anchor": ("checkpoint" if cp else "head"),
        "ledger_root_sha256": root,
        "leaf_sha256": merkle_mod._h(line_bytes).hex(),
        "proof": proof,
        "checkpoint": cp
    }


@app.get("/ledger/receipt/proof_bundle")
def ledger_receipt_proof_bundle(receipt_id: str):
    """
    Returns a self-contained verification bundle:
      - receipt envelope (key_id, payload_b64, signature_b64)
      - decoded receipt payload
      - governance rules + sigset + guardian_set
      - inclusion proof + anchor checkpoint (if any)
    Anyone can verify offline.
    """
    db = SessionLocal()
    try:
        r = db.query(Receipt).filter(Receipt.receipt_id == receipt_id).first()
        if not r:
            return {"ok": False, "error": "unknown_receipt_id"}

        envelope = {
            "key_id": str(r.key_id),
            "payload_b64": str(r.payload_b64),
            "signature_b64": str(r.signature_b64),
        }

        # decoded payload (best-effort)
        payload = None
        try:
            import base64, json as _json
            msg = base64.b64decode(envelope["payload_b64"].encode("ascii"))
            payload = _json.loads(msg.decode("utf-8"))
        except Exception:
            payload = None

        proof_obj = ledger_receipt_proof(receipt_id)  # reuse endpoint logic
        if not proof_obj.get("ok"):
            return {"ok": False, "error": "proof_failed", "detail": proof_obj}

        bundle = {
            "bundle_v": 1,
            "receipt_id": receipt_id,
            "envelope": envelope,
            "payload": payload,
            "governance": {
                "rules_version": GMF_GOV["rules_version"],
                "rules_sha256": GMF_GOV["rules_sha256"],
                "guardian_set_id": GMF_GOV["guardian_set_id"],
                "rules": GMF_GOV["rules"],
                "sigset": GMF_GOV["sigset"],
                "guardian_set": GMF_GOV["guardian_set"],
                "rules_registry_path": GMF_GOV.get("rules_registry_path", "governance/rules/registry.json"),
                "rules_registry": __import__("json").load(open(GMF_GOV.get("rules_registry_path", "governance/rules/registry.json"), "r", encoding="utf-8")),
                "rules_amendments_dir": __import__("os").environ.get("GMF_RULES_AMENDMENTS_DIR", "governance/rules/amendments"),

                "registry": GMF_GOV.get("registry", {}),
                "transitions_dir": "governance/signers/transitions",
                "attestations_dir": "ledger/attestations",

            },
            "inclusion": proof_obj,
        }
        return {"ok": True, "bundle": bundle}
    finally:
        db.close()


@app.get("/ledger/cache/status")
def ledger_cache_status():
    mc = MerkleCache(os.environ.get("GMF_MERKLE_DB", "ledger/cache/merkle_nodes.sqlite"))
    n = 0
    try:
        n = ledger_mod.ledger_entries_meta()
    except Exception:
        n = 0
    return {
        "ledger_entries": int(n),
        "cached_nodes": mc.count_nodes(),
        "prewarm_n_leaves": mc.meta_get_int("prewarm_n_leaves"),
        "prewarm_upto_level": mc.meta_get_int("prewarm_upto_level"),
        "prewarm_complete": mc.meta_get_int("prewarm_complete"),
    }

@app.post("/ledger/cache/prewarm")
def ledger_cache_prewarm(budget_nodes: int = 200000):
    """
    Prewarm internal Merkle nodes up to root level for current ledger length.
    Run this periodically (or before issuing a checkpoint) to stabilize performance.
    """
    mc = MerkleCache(os.environ.get("GMF_MERKLE_DB", "ledger/cache/merkle_nodes.sqlite"))
    n = ledger_mod.ledger_entries_meta()
    if n <= 0:
        return {"ok": True, "n_leaves": 0}
    from app.crypto.merkle_cache import root_level
    upto = root_level(n)
    res = mc.prewarm(n, upto_level=upto, budget_nodes=int(budget_nodes))
    return {"ok": True, "n_leaves": int(n), "upto_level": int(upto), "res": res, "cached_nodes": mc.count_nodes()}


@app.get("/ledger/checkpoint/status")
def ledger_checkpoint_status():
    """
    Returns how far the latest signed checkpoint lags behind the current ledger head.
    """
    head_root, head_n = checkpointing.current_ledger_root_and_len()
    cp = checkpointing.latest_checkpoint()
    if not cp:
        return {
            "ok": True,
            "has_checkpoint": False,
            "head_entries": int(head_n),
            "head_root_sha256": head_root,
            "checkpoint_entries": 0,
            "checkpoint_root_sha256": None,
            "lag_entries": int(head_n),
        }

    cpn = int(cp.get("entries") or 0)
    cpr = str(cp.get("ledger_root_sha256") or "")
    return {
        "ok": True,
        "has_checkpoint": True,
        "head_entries": int(head_n),
        "head_root_sha256": head_root,
        "checkpoint_entries": cpn,
        "checkpoint_root_sha256": cpr,
        "lag_entries": int(head_n - cpn),
        "checkpoint": cp
    }


@app.get("/ledger/checkpoint/pending/latest")
def ledger_checkpoint_pending_latest():
    p = checkpointing.latest_pending_checkpoint()
    return {"ok": bool(p), "pending": p}

@app.get("/ledger/checkpoint/pending/list")
def ledger_checkpoint_pending_list(limit: int = 20):
    files = checkpointing.list_pending_checkpoints(limit=int(limit))
    return {"ok": True, "limit": int(limit), "files": files}


@app.get("/governance/guardian_sets")
def governance_guardian_sets():
    reg = GMF_GOV.get("registry", {}) or {}
    return {"ok": True, "active_guardian_set_id": reg.get("active_guardian_set_id"), "sets": reg.get("sets", {})}

@app.get("/governance/guardian_sets/{guardian_set_id}")
def governance_guardian_set_get(guardian_set_id: str):
    reg = GMF_GOV.get("registry", {}) or {}
    sets = reg.get("sets", {}) or {}
    if guardian_set_id not in sets:
        return {"ok": False, "error": "unknown_guardian_set_id"}
    path = str(sets[guardian_set_id])
    try:
        import json
        g = json.load(open(path, "r", encoding="utf-8"))
        return {"ok": True, "guardian_set_id": guardian_set_id, "path": path, "guardian_set": g}
    except Exception:
        return {"ok": False, "error": "failed_to_load_guardian_set", "path": path}


@app.get("/governance/rules/registry")
def governance_rules_registry():
    import json
    path = GMF_GOV.get("rules_registry_path", "governance/rules/registry.json")
    try:
        return {"ok": True, "path": path, "registry": json.load(open(path, "r", encoding="utf-8"))}
    except Exception:
        return {"ok": False, "error": "failed_to_load_registry", "path": path}

@app.get("/governance/rules/active")
def governance_rules_active():
    return {
        "ok": True,
        "rules_version": GMF_GOV.get("rules_version"),
        "rules_sha256": GMF_GOV.get("rules_sha256"),
        "rules_path": GMF_GOV.get("rules_path"),
        "sigset_guardian_set_id": GMF_GOV.get("sigset_guardian_set_id"),
        "head_checkpoint_entries": __import__("app.crypto.rules_registry").crypto.rules_registry.latest_checkpoint_entries()
    }

@app.post("/governance/rules/amendments/submit")
def governance_rules_amendments_submit(amendment: dict):
    """
    Accept a threshold-signed rules amendment, store it, and append to rules registry.
    """
    res = amendments.apply_amendment(amendment)
    return {"ok": True, **res}


@app.get("/governance/rules/amendments/list")
def governance_rules_amendments_list(limit: int = 50):
    import os, json
    d = os.environ.get("GMF_RULES_AMENDMENTS_DIR", "governance/rules/amendments")
    try:
        files = [fn for fn in os.listdir(d) if fn.endswith(".json")]
        files.sort()
        files = files[-max(1, min(500, int(limit))):]
        return {"ok": True, "dir": d, "files": files}
    except Exception as e:
        return {"ok": False, "error": "failed_to_list", "dir": d, "detail": str(e)}

@app.get("/governance/rules/amendments/get")
def governance_rules_amendments_get(name: str):
    import os, json
    d = os.environ.get("GMF_RULES_AMENDMENTS_DIR", "governance/rules/amendments")
    path = os.path.join(d, name)
    try:
        obj = json.load(open(path, "r", encoding="utf-8"))
        return {"ok": True, "path": path, "amendment": obj}
    except Exception as e:
        return {"ok": False, "error": "failed_to_load", "path": path, "detail": str(e)}


# Work API
app.include_router(work_router)
app.include_router(devices_router)

# Credits API
app.include_router(credits_router)

# Enroll API
app.include_router(enroll_router)

# Policy API
app.include_router(policy_router)

# Verification API
app.include_router(verification_router)
