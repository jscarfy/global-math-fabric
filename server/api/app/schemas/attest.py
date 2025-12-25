from pydantic import BaseModel
from typing import Any, Dict

class DeviceAttestRequest(BaseModel):
    device_id: str
    level: str          # e.g. "none" | "basic" | "strong"
    doc: Dict[str, Any] # opaque attestation payload (token, headers, etc.)

class DeviceAttestResponse(BaseModel):
    accepted: bool
    note: str
