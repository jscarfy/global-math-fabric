import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Integer, Boolean, Text, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base

class Client(Base):
    __tablename__ = "clients"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    api_key_hash: Mapped[str] = mapped_column(String(64), index=True)  # sha256 hex
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    credits_total: Mapped[int] = mapped_column(Integer, default=0, index=True)

    events = relationship("CreditEvent", back_populates="client", cascade="all, delete-orphan")


class CreditEvent(Base):
    __tablename__ = "credit_events"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id_fk: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("clients.id", ondelete="CASCADE"), index=True)

    kind: Mapped[str] = mapped_column(String(40), index=True)  # report_accepted | instance_verified | bonus
    points: Mapped[int] = mapped_column(Integer, default=0)
    meta: Mapped[dict] = mapped_column(JSONB, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)

    client = relationship("Client", back_populates="events")
