from datetime import timedelta
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import (
    as_utc,
    create_access_token,
    generate_refresh_token,
    hash_token,
    utcnow,
    verify_password,
)
from app.models.refresh_token import RefreshToken
from app.models.session import Session
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.session_repository import SessionRepository
from app.repositories.user_repository import UserRepository
from app.services.audit_service import AuditService
from app.services.permission_service import permissions_for_role


class AuthService:
    def __init__(
        self,
        *,
        db: AsyncSession,
        user_repo: UserRepository,
        session_repo: SessionRepository,
        refresh_repo: RefreshTokenRepository,
        audit_service: AuditService,
    ) -> None:
        self.db = db
        self.user_repo = user_repo
        self.session_repo = session_repo
        self.refresh_repo = refresh_repo
        self.audit_service = audit_service

    async def login(
        self, *, email: str, password: str, device_id: str, ip_address: str | None, user_agent: str | None
    ) -> dict:
        user = await self.user_repo.get_by_email(email)
        if not user or not verify_password(password, user.password_hash):
            await self.audit_service.log(action="failed_login", user_id=user.id if user else None, ip_address=ip_address)
            await self.db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        if not user.is_active or user.is_compromised:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account unavailable")

        session = await self.session_repo.create(
            Session(user_id=user.id, device_id=device_id, ip_address=ip_address, user_agent=user_agent)
        )
        token_pair = await self._issue_token_pair(
            user_id=user.id,
            role=user.role,
            session_id=session.id,
            device_id=device_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await self.audit_service.log(action="login", user_id=user.id, ip_address=ip_address)
        await self.db.commit()
        return token_pair

    async def refresh(
        self, *, refresh_token: str, device_id: str, ip_address: str | None, user_agent: str | None
    ) -> dict:
        token_hash = hash_token(refresh_token)
        existing = await self.refresh_repo.get_by_hash(token_hash)
        if not existing:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

        user = await self.user_repo.get_by_id(existing.user_id)
        if not user or not user.is_active or user.is_compromised:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account unavailable")

        if existing.revoked_at is not None:
            await self._handle_replay(existing, ip_address)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token replay detected")
        if as_utc(existing.expires_at) <= utcnow():
            await self.refresh_repo.revoke(existing)
            await self.db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
        if existing.device_id != device_id:
            await self.audit_service.log(action="refresh_device_mismatch", user_id=user.id, ip_address=ip_address)
            await self.db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device")

        session = await self.session_repo.get_active(existing.session_id, user.id)
        if not session:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked")

        raw_new_refresh = generate_refresh_token()
        new_hash = hash_token(raw_new_refresh)
        await self.refresh_repo.revoke(existing, replaced_by_token_hash=new_hash)
        session.last_used_at = utcnow()
        token_pair = await self._issue_token_pair(
            user_id=user.id,
            role=user.role,
            session_id=session.id,
            device_id=device_id,
            ip_address=ip_address,
            user_agent=user_agent,
            raw_refresh_token=raw_new_refresh,
            refresh_token_hash=new_hash,
        )
        await self.audit_service.log(action="refresh", user_id=user.id, ip_address=ip_address)
        await self.db.commit()
        return token_pair

    async def logout(self, *, user_id: UUID, refresh_token: str, device_id: str, ip_address: str | None) -> None:
        token = await self.refresh_repo.get_by_hash(hash_token(refresh_token))
        if token and token.user_id == user_id and token.device_id == device_id:
            await self.refresh_repo.revoke(token)
            await self.refresh_repo.revoke_session_tokens(token.session_id)
            session = await self.session_repo.get_active(token.session_id, user_id)
            if session:
                await self.session_repo.revoke(session)
        await self.audit_service.log(action="logout", user_id=user_id, ip_address=ip_address)
        await self.db.commit()

    async def logout_all(self, *, user_id: UUID, ip_address: str | None) -> None:
        await self.refresh_repo.revoke_all_for_user(user_id)
        await self.session_repo.revoke_all_for_user(user_id)
        await self.audit_service.log(action="logout_all", user_id=user_id, ip_address=ip_address)
        await self.db.commit()

    async def list_sessions(self, *, user_id: UUID) -> list[Session]:
        return await self.session_repo.list_active_for_user(user_id)

    async def revoke_session(self, *, user_id: UUID, session_id: UUID, ip_address: str | None) -> None:
        session = await self.session_repo.get_active(session_id, user_id)
        if not session:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
        await self.session_repo.revoke(session)
        await self.refresh_repo.revoke_session_tokens(session.id)
        await self.audit_service.log(action="session_revoked", user_id=user_id, ip_address=ip_address)
        await self.db.commit()

    async def _issue_token_pair(
        self,
        *,
        user_id: UUID,
        role: str,
        session_id: UUID,
        device_id: str,
        ip_address: str | None,
        user_agent: str | None,
        raw_refresh_token: str | None = None,
        refresh_token_hash: str | None = None,
    ) -> dict:
        permissions = permissions_for_role(role)
        access_token, jti, access_expires_at = create_access_token(user_id=user_id, role=role, permissions=permissions)
        raw_refresh_token = raw_refresh_token or generate_refresh_token()
        refresh_token_hash = refresh_token_hash or hash_token(raw_refresh_token)
        refresh_expires_at = utcnow() + timedelta(days=settings.refresh_token_expire_days)
        await self.refresh_repo.create(
            RefreshToken(
                user_id=user_id,
                session_id=session_id,
                refresh_token_hash=refresh_token_hash,
                device_id=device_id,
                ip_address=ip_address,
                user_agent=user_agent,
                expires_at=refresh_expires_at,
            )
        )
        return {
            "access_token": access_token,
            "refresh_token": raw_refresh_token,
            "token_type": "bearer",
            "expires_in": settings.access_token_expire_minutes * 60,
            "access_jti": jti,
            "access_expires_at": access_expires_at,
            "refresh_max_age": settings.refresh_token_expire_days * 24 * 60 * 60,
        }

    async def _handle_replay(self, token: RefreshToken, ip_address: str | None) -> None:
        await self.refresh_repo.mark_replay(token)
        user = await self.user_repo.get_by_id(token.user_id)
        if user:
            await self.user_repo.mark_compromised(user)
            await self.refresh_repo.revoke_all_for_user(user.id)
            await self.session_repo.revoke_all_for_user(user.id)
            await self.audit_service.log(action="refresh_replay_detected", user_id=user.id, ip_address=ip_address)
        await self.db.commit()
