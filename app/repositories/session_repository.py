from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import utcnow
from app.models.session import Session


class SessionRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(self, session: Session) -> Session:
        self.db.add(session)
        await self.db.flush()
        return session

    async def get_active(self, session_id: UUID, user_id: UUID) -> Session | None:
        result = await self.db.execute(
            select(Session).where(Session.id == session_id, Session.user_id == user_id, Session.revoked_at.is_(None))
        )
        return result.scalar_one_or_none()

    async def list_active_for_user(self, user_id: UUID) -> list[Session]:
        result = await self.db.execute(
            select(Session)
            .where(Session.user_id == user_id, Session.revoked_at.is_(None))
            .order_by(Session.last_used_at.desc())
        )
        return list(result.scalars())

    async def revoke(self, session: Session) -> None:
        session.revoked_at = utcnow()
        await self.db.flush()

    async def revoke_all_for_user(self, user_id: UUID) -> None:
        await self.db.execute(
            update(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None)).values(revoked_at=utcnow())
        )

