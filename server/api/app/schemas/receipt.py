from pydantic import BaseModel
from typing import Any, Dict, List

class ReceiptRow(BaseModel):
    instance_id: str
    credits_delta: int
    body: Dict[str, Any]
    sig_key_id: str
    signature_b64: str
    created_at: str

class ReceiptsResponse(BaseModel):
    receipts: List[ReceiptRow]
