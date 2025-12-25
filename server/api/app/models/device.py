import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id_fk: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("clients.id", ondelete="CASCADE"), index=True)

    pubkey_b64: Mapped[str] = mapped_column(String(128), index=True, unique=True)
    label: Mapped[str | None] = mapped_column(String(200), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    attestation_level: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    attestation_doc: Mapped[dict] = mapped_column(JSONB, default=dict)
    attested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_capabilities: Mapped[dict] = mapped_column(JSONB, default=dict)

    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)

class DeviceChallenge(Base):
    __tablename__ = "device_challenges"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id_fk: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), index=True)

    nonce: Mapped[str] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    used: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

class Heartbeat(Base):
    __tablename__ = "heartbeats"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id_fk: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), index=True)

    payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
