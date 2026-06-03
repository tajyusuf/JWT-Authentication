from uuid import UUID

from app.models.audit_log import AuditLog
from app.repositories.audit_repository import AuditRepository


class AuditService:
    def __init__(self, audit_repo: AuditRepository) -> None:
        self.audit_repo = audit_repo

    async def log(self, *, action: str, user_id: UUID | None, ip_address: str | None) -> None:
        await self.audit_repo.add(AuditLog(action=action, user_id=user_id, ip_address=ip_address))

