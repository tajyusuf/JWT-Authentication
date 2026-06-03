from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from redis.asyncio import Redis

from app.core.config import settings
from app.core.cookies import clear_auth_cookies, set_auth_cookies
from app.core.redis import get_redis
from app.dependencies.auth import get_current_user, require_role
from app.dependencies.services import get_auth_service
from app.schemas.auth import CurrentUser, LoginRequest, LogoutRequest, RefreshRequest, TokenPair
from app.schemas.session import SessionOut
from app.services.auth_service import AuthService
from app.services.token_service import TokenBlacklistService
from app.utils.request import client_ip, user_agent

router = APIRouter()


@router.post("/login", response_model=TokenPair)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
) -> TokenPair:
    tokens = await auth_service.login(
        email=payload.email,
        password=payload.password,
        device_id=payload.device_id,
        ip_address=client_ip(request),
        user_agent=user_agent(request),
    )
    set_auth_cookies(
        response,
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        access_expires_at=tokens["access_expires_at"],
        refresh_max_age=tokens["refresh_max_age"],
    )
    return TokenPair(**tokens)


@router.post("/refresh", response_model=TokenPair)
async def refresh(
    payload: RefreshRequest,
    request: Request,
    response: Response,
    refresh_cookie: str | None = Cookie(default=None, alias=settings.refresh_cookie_name),
    auth_service: AuthService = Depends(get_auth_service),
) -> TokenPair:
    refresh_token = payload.refresh_token or refresh_cookie
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")
    tokens = await auth_service.refresh(
        refresh_token=refresh_token,
        device_id=payload.device_id,
        ip_address=client_ip(request),
        user_agent=user_agent(request),
    )
    set_auth_cookies(
        response,
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        access_expires_at=tokens["access_expires_at"],
        refresh_max_age=tokens["refresh_max_age"],
    )
    return TokenPair(**tokens)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    payload: LogoutRequest,
    request: Request,
    response: Response,
    current_user: CurrentUser = Depends(get_current_user),
    refresh_cookie: str | None = Cookie(default=None, alias=settings.refresh_cookie_name),
    auth_service: AuthService = Depends(get_auth_service),
    redis: Redis = Depends(get_redis),
) -> None:
    refresh_token = payload.refresh_token or refresh_cookie
    if refresh_token:
        await auth_service.logout(
            user_id=current_user.id,
            refresh_token=refresh_token,
            device_id=payload.device_id,
            ip_address=client_ip(request),
        )
    await TokenBlacklistService(redis).blacklist_jti(current_user.jti, current_user.exp)
    clear_auth_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
    request: Request,
    response: Response,
    current_user: CurrentUser = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
    redis: Redis = Depends(get_redis),
) -> None:
    await auth_service.logout_all(user_id=current_user.id, ip_address=client_ip(request))
    await TokenBlacklistService(redis).blacklist_jti(current_user.jti, current_user.exp)
    clear_auth_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT


@router.get("/sessions", response_model=list[SessionOut])
async def sessions(
    current_user: CurrentUser = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> list[SessionOut]:
    return [SessionOut.model_validate(session, from_attributes=True) for session in await auth_service.list_sessions(user_id=current_user.id)]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: UUID,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> None:
    await auth_service.revoke_session(user_id=current_user.id, session_id=session_id, ip_address=client_ip(request))


@router.get("/admin/ping")
async def admin_ping(_: CurrentUser = Depends(require_role("admin"))) -> dict[str, str]:
    return {"status": "ok"}
