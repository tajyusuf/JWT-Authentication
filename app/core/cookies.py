from datetime import datetime

from fastapi import Response

from app.core.config import settings


def set_auth_cookies(
    response: Response,
    *,
    access_token: str,
    refresh_token: str,
    access_expires_at: datetime,
    refresh_max_age: int,
) -> None:
    access_max_age = max(int((access_expires_at.timestamp() - datetime.now(access_expires_at.tzinfo).timestamp())), 0)
    response.set_cookie(
        settings.access_cookie_name,
        access_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=access_max_age,
    )
    response.set_cookie(
        settings.refresh_cookie_name,
        refresh_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=refresh_max_age,
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(settings.access_cookie_name)
    response.delete_cookie(settings.refresh_cookie_name)

