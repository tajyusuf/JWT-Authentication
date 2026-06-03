from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "FastAPI Auth Service"
    environment: Literal["development", "staging", "production", "test"] = "development"
    debug: bool = False

    database_url: str = "postgresql+asyncpg://auth:auth@localhost:5432/auth"
    redis_url: str = "redis://localhost:6379/0"

    jwt_secret_key: str = Field(default="change-me-use-a-long-random-secret", min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30

    cookie_secure: bool = True
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    access_cookie_name: str = "access_token"
    refresh_cookie_name: str = "refresh_token"

    rate_limit_per_minute: int = 60


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

