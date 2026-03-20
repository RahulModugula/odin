import hashlib

from redis.asyncio import Redis

from app.models.schemas import ReviewResult


class CacheService:
    def __init__(self, redis: Redis):
        self.redis = redis
        self.ttl = 3600  # 1 hour

    def _make_key(self, code: str, language: str) -> str:
        content = f"{code}:{language}"
        return f"review:{hashlib.sha256(content.encode()).hexdigest()}"

    async def get(self, code: str, language: str) -> ReviewResult | None:
        key = self._make_key(code, language)
        data = await self.redis.get(key)
        if data:
            result = ReviewResult.model_validate_json(data)
            result.cached = True
            return result
        return None

    async def set(self, code: str, language: str, result: ReviewResult) -> None:
        key = self._make_key(code, language)
        await self.redis.set(key, result.model_dump_json(), ex=self.ttl)
