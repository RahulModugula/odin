"""Persistence for PR reviews using Redis."""
import json
from datetime import datetime

import structlog
from redis.asyncio import Redis

logger = structlog.get_logger()

TTL_30_DAYS = 2_592_000


class ReviewStore:
    def __init__(self, redis: Redis, ttl: int = TTL_30_DAYS):
        self.redis = redis
        self.ttl = ttl

    async def save(self, review_id: str, data: dict) -> None:  # type: ignore[type-arg]
        key = f"pr_review:{review_id}"
        payload = json.dumps({**data, "saved_at": datetime.utcnow().isoformat()})
        await self.redis.set(key, payload, ex=self.ttl)
        # Keep an index sorted by timestamp for listing
        await self.redis.zadd("pr_reviews:index", {review_id: datetime.utcnow().timestamp()})
        await self.redis.expire("pr_reviews:index", self.ttl)

    async def get(self, review_id: str) -> dict | None:  # type: ignore[type-arg]
        key = f"pr_review:{review_id}"
        data = await self.redis.get(key)
        if data:
            return json.loads(data)  # type: ignore[no-any-return]
        return None

    async def list_recent(self, limit: int = 20, offset: int = 0) -> list[dict]:  # type: ignore[type-arg]
        """Return recent reviews sorted by time (newest first)."""
        ids = await self.redis.zrevrange("pr_reviews:index", offset, offset + limit - 1)
        results = []
        for rid in ids:
            review_id = rid.decode() if isinstance(rid, bytes) else rid
            data = await self.get(review_id)
            if data:
                results.append(data)
        return results

    async def delete(self, review_id: str) -> None:
        await self.redis.delete(f"pr_review:{review_id}")
        await self.redis.zrem("pr_reviews:index", review_id)
