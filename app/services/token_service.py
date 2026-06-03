from redis.asyncio import Redis

from app.core.security import utcnow


class TokenBlacklistService:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def blacklist_jti(self, jti: str, exp: int) -> None:
        ttl = max(exp - int(utcnow().timestamp()), 0)
        if ttl > 0:
            await self.redis.setex(f"blacklist:jti:{jti}", ttl, "1")

    async def is_blacklisted(self, jti: str) -> bool:
        return bool(await self.redis.exists(f"blacklist:jti:{jti}"))

