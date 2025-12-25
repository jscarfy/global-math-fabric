from sqlalchemy import Column, String, Integer, Boolean, Text, DateTime, Index
from sqlalchemy.sql import func
from .work_db import BaseWork

class Job(BaseWork):
    __tablename__ = "jobs"
    job_id = Column(String, primary_key=True)
    kind = Column(String, nullable=False)              # e.g. "proof_search", "lemma_check", "toy_math"
    payload_json = Column(Text, nullable=False)        # canonical json string
    credits = Column(Integer, nullable=False, default=1)
    topic = Column(String, nullable=True, index=True)
    requires_lean = Column(Boolean, nullable=False, default=False)
    min_ram_mb = Column(Integer, nullable=False, default=0)
    min_disk_mb = Column(Integer, nullable=False, default=0)
    goal_key = Column(String, nullable=True, index=True)
    attempts = Column(Integer, nullable=False, default=0)
    accepted_once = Column(Boolean, nullable=False, default=False)
    status = Column(String, nullable=False, default="open")  # open|leased|done|cancelled
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class JobLease(BaseWork):
    __tablename__ = "job_leases"
    lease_id = Column(String, primary_key=True)
    job_id = Column(String, nullable=False, index=True)
    policy_hash = Column(String, nullable=False, default="")
    device_id = Column(String, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

Index("ix_job_leases_job_active", JobLease.job_id, JobLease.active)

class WorkResult(BaseWork):
    __tablename__ = "work_results"
    result_id = Column(String, primary_key=True)
    job_id = Column(String, nullable=False, index=True)
    device_id = Column(String, nullable=False, index=True)
    input_sha256 = Column(String, nullable=False)
    output_sha256 = Column(String, nullable=False)
    output_json = Column(Text, nullable=False)
    accepted = Column(Boolean, nullable=False, default=False)
    awarded_credits = Column(Integer, nullable=False, default=0)
    receipt_id = Column(String, nullable=True, index=True)  # maps to signed receipt envelope
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Device(BaseWork):
    __tablename__ = "devices"
    device_id = Column(String, primary_key=True)
    platform = Column(String, nullable=False, default="unknown")   # linux/macos/windows/android/ios/...
    has_lean = Column(Boolean, nullable=False, default=False)
    ram_mb = Column(Integer, nullable=False, default=0)
    disk_mb = Column(Integer, nullable=False, default=0)
    topics_csv = Column(Text, nullable=True)                       # e.g. "algebra,nt,topology"
    pubkey_b64 = Column(Text, nullable=True)                       # device ed25519 public key (base64, 32 bytes)
    enroll_ref = Column(Text, nullable=True, index=True)           # sha256(token) to bind receipts forever
    policy_version = Column(String, nullable=True)                 # e.g. v1
    policy_hash = Column(Text, nullable=True, index=True)          # sha256(canonical policy json)
    daily_credit_limit = Column(Integer, nullable=False, default=0) # 0 => unlimited for this device
    meta_json = Column(Text, nullable=True)                        # canonical json string
    last_seen_at = Column(DateTime(timezone=True), server_default=func.now())

class DeviceDaily(BaseWork):
    __tablename__ = "device_daily"
    id = Column(String, primary_key=True)                          # device_id|YYYY-MM-DD
    device_id = Column(String, nullable=False, index=True)
    day = Column(String, nullable=False, index=True)               # YYYY-MM-DD (UTC)
    credits_awarded = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

Index("ix_jobs_topic", Job.topic)


class LeaseChallenge(Base):
    __tablename__ = "lease_challenges"
    id = Column(Integer, primary_key=True, autoincrement=True)
    lease_id = Column(String, nullable=False, unique=True, index=True)
    device_id = Column(String, nullable=False, index=True)
    job_id = Column(String, nullable=False, index=True)
    nonce_hex = Column(String, nullable=False)          # server-issued nonce
    sample_k = Column(Integer, nullable=False, default=3)
    chunk_size = Column(Integer, nullable=False, default=65536)
    seed_hex = Column(String, nullable=False, default="")  # sha256(lease_id|nonce)
    audit_required = Column(Integer, nullable=False, default=0)  # 0/1
    required_fields_csv = Column(Text, nullable=False, default="")  # e.g. "lean_trace_hash"
    created_ts_utc = Column(String, nullable=False)

