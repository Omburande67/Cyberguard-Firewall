from pydantic import BaseModel
from datetime import datetime

class AttackEvent(BaseModel):
    id: int | None = None
    source_ip: str
    path: str
    payload: str
    attack_type: str
    severity: str
    timestamp: datetime = datetime.utcnow()
