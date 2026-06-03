import os
from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-that-is-long-enough-for-jwt"
os.environ["COOKIE_SECURE"] = "false"

from app.core.db import get_db
from app.core.redis import get_redis
from app.core.security import hash_password
from app.main import create_app
from app.models import Base
from app.models.user import User


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self.store[key] = value

    async def exists(self, key: str) -> int:
        return int(key in self.store)

    async def incr(self, key: str) -> int:
        self.store[key] = str(int(self.store.get(key, "0")) + 1)
        return int(self.store[key])

    async def expire(self, key: str, ttl: int) -> None:
        return None


@pytest.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with SessionLocal() as session:
        session.add(
            User(
                email="user@example.com",
                password_hash=hash_password("correct-password"),
                role="user",
            )
        )
        session.add(
            User(
                email="admin@example.com",
                password_hash=hash_password("correct-password"),
                role="admin",
            )
        )
        await session.commit()

    async def override_db() -> AsyncGenerator[AsyncSession, None]:
        async with SessionLocal() as session:
            yield session

    fake_redis = FakeRedis()

    async def override_redis() -> AsyncGenerator[FakeRedis, None]:
        yield fake_redis

    app = create_app()
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_redis] = override_redis

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as test_client:
        yield test_client

    await engine.dispose()

