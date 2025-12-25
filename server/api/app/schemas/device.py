from pydantic import BaseModel
from typing import Any, Dict, Optional

class DeviceRegisterRequest(BaseModel):
    pubkey_b64: str
    label: Optional[str] = None
    platform: Optional[str] = None

class DeviceRegisterResponse(BaseModel):
    device_id: str
    note: str

class DeviceChallengeResponse(BaseModel):
    device_id: str
    nonce: str
    note: str

class HeartbeatRequest(BaseModel):
    device_id: str
    payload: Dict[str, Any]

class HeartbeatResponse(BaseModel):
    accepted: bool
    note: str
