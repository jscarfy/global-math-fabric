from pydantic import BaseModel, Field
from typing import Optional

class RegisterRequest(BaseModel):
    client_id: str = Field(min_length=3, max_length=200)
    display_name: Optional[str] = Field(default=None, max_length=200)

class RegisterResponse(BaseModel):
    client_id: str
    api_key: str
