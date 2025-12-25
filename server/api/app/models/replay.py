import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base

class ReplayCheck(Base):
    __tablename__ = "replay_checks"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    instance_id_fk: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("task_instances.id", ondelete="CASCADE"), index=True)
    ok: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    verifier_id: Mapped[str] = mapped_column(String(200), index=True)
    meta: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
