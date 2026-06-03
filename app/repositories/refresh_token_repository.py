from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import utcnow
from app.models.refresh_token import RefreshToken


class RefreshTokenRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(self, token: RefreshToken) -> RefreshToken:
        self.db.add(token)
        await self.db.flush()
        return token

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        result = await self.db.execute(select(RefreshToken).where(RefreshToken.refresh_token_hash == token_hash))
        return result.scalar_one_or_none()

    async def revoke(self, token: RefreshToken, replaced_by_token_hash: str | None = None) -> None:
        token.revoked_at = utcnow()
        token.last_used_at = utcnow()
        token.replaced_by_token_hash = replaced_by_token_hash
        await self.db.flush()

    async def revoke_session_tokens(self, session_id: UUID) -> None:
        await self.db.execute(
            update(RefreshToken)
            .where(RefreshToken.session_id == session_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )

    async def revoke_all_for_user(self, user_id: UUID) -> None:
        await self.db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )

    async def mark_replay(self, token: RefreshToken) -> None:
        token.replay_detected_at = utcnow()
        await self.db.flush()

