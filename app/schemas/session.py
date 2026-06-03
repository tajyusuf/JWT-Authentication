from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class SessionOut(BaseModel):
    id: UUID
    device_id: str
    ip_address: str | None
    user_agent: str | None
    created_at: datetime
    last_used_at: datetime

