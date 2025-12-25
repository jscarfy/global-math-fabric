from pydantic import BaseModel
from typing import Any, Dict, Optional

class ReplayQueueItem(BaseModel):
    instance_id: str
    manifest: Dict[str, Any]
    wasm_b64: str
    input_json: Dict[str, Any]
    winning_sha256: str

class ReplayQueueResponse(BaseModel):
    item: Optional[ReplayQueueItem] = None
    note: str

class ReplayReportRequest(BaseModel):
    instance_id: str
    verifier_id: str
    ok: bool
    detail: Dict[str, Any] = {}

class ReplayReportResponse(BaseModel):
    accepted: bool
    note: str
