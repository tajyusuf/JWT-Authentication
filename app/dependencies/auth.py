from collections.abc import Callable
from uuid import UUID

import jwt
from fastapi import Cookie, Depends, Header, HTTPException, status
from redis.asyncio import Redis

from app.core.config import settings
from app.core.redis import get_redis
from app.core.security import decode_access_token
from app.schemas.auth import CurrentUser
from app.services.token_service import TokenBlacklistService


async def get_current_user(
    authorization: str | None = Header(default=None),
    access_cookie: str | None = Cookie(default=None, alias=settings.access_cookie_name),
    redis: Redis = Depends(get_redis),
) -> CurrentUser:
    token = access_cookie
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing access token")

    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token") from exc

    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    jti = payload.get("jti")
    if not jti or await TokenBlacklistService(redis).is_blacklisted(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token revoked")

    return CurrentUser(
        id=UUID(payload["sub"]),
        role=payload["role"],
        permissions=list(payload.get("permissions", [])),
        jti=jti,
        exp=int(payload["exp"]),
    )


def require_role(role: str) -> Callable:
    async def dependency(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.role != role:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return current_user

    return dependency


def require_permission(permission: str) -> Callable:
    async def dependency(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if permission not in current_user.permissions:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permission")
        return current_user

    return dependency

