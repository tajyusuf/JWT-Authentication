from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


class AuditRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def add(self, log: AuditLog) -> AuditLog:
        self.db.add(log)
        await self.db.flush()
        return log

