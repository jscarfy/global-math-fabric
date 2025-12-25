from pydantic import BaseModel
from typing import Any, Dict

class ReceiptEnvelope(BaseModel):
    key_id: str
    payload_b64: str
    signature_b64: str
