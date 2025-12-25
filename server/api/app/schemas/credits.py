from pydantic import BaseModel
from typing import List, Optional

class MeResponse(BaseModel):
    client_id: str
    display_name: Optional[str] = None
    credits_total: int

class LeaderboardRow(BaseModel):
    client_id: str
    display_name: Optional[str] = None
    credits_total: int

class LeaderboardResponse(BaseModel):
    rows: List[LeaderboardRow]
