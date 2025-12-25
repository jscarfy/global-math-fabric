import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Integer, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base

class Receipt(Base):
    __tablename__ = "receipts"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    instance_id_fk: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("task_instances.id", ondelete="CASCADE"), index=True)
    issued_to_client_id: Mapped[str] = mapped_column(String(200), index=True)
    credits_delta: Mapped[int] = mapped_column(Integer, default=0)
    body: Mapped[dict] = mapped_column(JSONB, default=dict)
    sig_key_id: Mapped[str] = mapped_column(String(200), index=True)
    signature_b64: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
