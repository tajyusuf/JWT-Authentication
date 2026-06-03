from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.repositories.audit_repository import AuditRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.session_repository import SessionRepository
from app.repositories.user_repository import UserRepository
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService


def get_auth_service(db: AsyncSession = Depends(get_db)) -> AuthService:
    return AuthService(
        db=db,
        user_repo=UserRepository(db),
        session_repo=SessionRepository(db),
        refresh_repo=RefreshTokenRepository(db),
        audit_service=AuditService(AuditRepository(db)),
    )

