"""Feedback tracking for improving review quality over time."""
import hashlib
import json
from datetime import datetime

import structlog
from redis.asyncio import Redis

logger = structlog.get_logger()


class FeedbackService:
    """Track user feedback on findings to build team-specific suppressions."""

    def __init__(self, redis: Redis):
        self.redis = redis
        self._prefix = "feedback:"
        self._suppression_prefix = "suppress:"

    def _finding_fingerprint(self, category: str, title_pattern: str, language: str) -> str:
        key = f"{category}:{title_pattern}:{language}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    async def record(
        self,
        finding_id: str,
        action: str,  # "helpful" | "not_helpful" | "false_positive"
        category: str,
        title: str,
        language: str,
    ) -> None:
        fp = self._finding_fingerprint(category, title[:50], language)
        key = f"{self._prefix}{fp}"

        entry = {
            "finding_id": finding_id,
            "action": action,
            "category": category,
            "title": title,
            "language": language,
            "ts": datetime.utcnow().isoformat(),
        }

        await self.redis.lpush(key, json.dumps(entry))
        await self.redis.ltrim(key, 0, 99)  # keep last 100

        # If marked as false positive 3+ times, add to suppressions
        all_entries = await self.redis.lrange(key, 0, -1)
        fp_count = sum(1 for e in all_entries if json.loads(e).get("action") == "false_positive")
        if fp_count >= 3:
            await self.redis.set(f"{self._suppression_prefix}{fp}", "1", ex=86400 * 90)  # 90 days
            logger.info("added suppression", fingerprint=fp, title=title)

    async def get_suppressions(self) -> list[str]:
        """Return list of suppressed finding fingerprints."""
        keys = []
        async for key in self.redis.scan_iter(f"{self._suppression_prefix}*"):
            keys.append(key.decode().replace(self._suppression_prefix, ""))
        return keys

    async def is_suppressed(self, category: str, title: str, language: str) -> bool:
        fp = self._finding_fingerprint(category, title[:50], language)
        return await self.redis.exists(f"{self._suppression_prefix}{fp}") > 0
