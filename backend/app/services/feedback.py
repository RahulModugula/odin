"""Feedback tracking for improving review quality over time."""

import hashlib
import json
from datetime import UTC, datetime

import structlog
from redis.asyncio import Redis

logger = structlog.get_logger()

# Taint-pair suppression kicks in after this many FP reports — lower than the
# general threshold because source→sink pairs are highly specific.
_TAINT_PAIR_FP_THRESHOLD = 2


class FeedbackService:
    """Track user feedback on findings to build team-specific suppressions.

    Two suppression namespaces:
      suppress:{fingerprint}           — general finding suppressions (rule/AI)
      suppress:taint:{source}:{sink}   — dataflow taint-pair suppressions

    Taint-pair suppressions trigger at 2 FP reports (vs 3 for general) because
    they are source→sink specific and therefore much less likely to be
    coincidental. They also fire *before* the LLM triage stage runs, saving
    token spend — not just reducing UI noise.
    """

    def __init__(self, redis: Redis):
        self.redis = redis
        self._prefix = "feedback:"
        self._suppression_prefix = "suppress:"
        self._taint_prefix = "suppress:taint:"

    def _finding_fingerprint(self, category: str, title_pattern: str, language: str) -> str:
        key = f"{category}:{title_pattern}:{language}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _taint_pair_key(self, source_sig: str, sink_sig: str) -> str:
        return f"{self._taint_prefix}{source_sig}:{sink_sig}"

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
            "ts": datetime.now(UTC).isoformat(),
        }

        await self.redis.lpush(key, json.dumps(entry))
        await self.redis.ltrim(key, 0, 99)  # keep last 100

        # If marked as false positive 3+ times, add to suppressions
        all_entries = await self.redis.lrange(key, 0, -1)
        fp_count = sum(1 for e in all_entries if json.loads(e).get("action") == "false_positive")
        if fp_count >= 3:
            await self.redis.set(f"{self._suppression_prefix}{fp}", "1", ex=86400 * 90)  # 90 days
            logger.info("added suppression", fingerprint=fp, title=title)

    async def record_taint_false_positive(
        self,
        source_sig: str,
        sink_sig: str,
        language: str,
        candidate_id: str,
    ) -> None:
        """Record a taint-pair false positive and suppress after threshold.

        Suppression fires before LLM triage (in the candidate extractor),
        reducing token spend — not just UI noise.
        """
        key = f"{self._taint_prefix}fp:{source_sig}:{sink_sig}"

        entry = {
            "candidate_id": candidate_id,
            "language": language,
            "ts": datetime.now(UTC).isoformat(),
        }
        await self.redis.lpush(key, json.dumps(entry))
        await self.redis.ltrim(key, 0, 49)

        all_entries = await self.redis.lrange(key, 0, -1)
        if len(all_entries) >= _TAINT_PAIR_FP_THRESHOLD:
            suppress_key = self._taint_pair_key(source_sig, sink_sig)
            await self.redis.set(suppress_key, "1", ex=86400 * 90)  # 90 days
            logger.info(
                "taint pair suppressed",
                source_sig=source_sig,
                sink_sig=sink_sig,
                language=language,
            )

    async def is_taint_pair_suppressed(self, source_sig: str, sink_sig: str) -> bool:
        """Return True if this source→sink pair is suppressed."""
        key = self._taint_pair_key(source_sig, sink_sig)
        return await self.redis.exists(key) > 0

    async def filter_taint_candidates(
        self,
        candidates: list,  # list[TaintCandidate] — avoid circular import
    ) -> list:
        """Remove suppressed source→sink pairs from the candidate list.

        Called inside the dataflow node, before the LLM triage stage.
        This is the key distinction: suppression saves LLM spend, not just
        post-hoc UI filtering.
        """
        filtered = []
        suppressed_count = 0
        for c in candidates:
            if await self.is_taint_pair_suppressed(c.source.signature, c.sink.signature):
                suppressed_count += 1
                logger.debug(
                    "taint candidate suppressed pre-triage",
                    source=str(c.source.kind),
                    sink=str(c.sink.kind),
                )
            else:
                filtered.append(c)

        if suppressed_count:
            logger.info(
                "pre-triage suppression",
                suppressed=suppressed_count,
                remaining=len(filtered),
            )
        return filtered

    async def get_suppressions(self) -> list[str]:
        """Return list of suppressed finding fingerprints."""
        keys = []
        async for key in self.redis.scan_iter(f"{self._suppression_prefix}*"):
            fp = key.decode().replace(self._suppression_prefix, "")
            # Exclude taint-pair keys from this list
            if not fp.startswith("taint:"):
                keys.append(fp)
        return keys

    async def is_suppressed(self, category: str, title: str, language: str) -> bool:
        fp = self._finding_fingerprint(category, title[:50], language)
        return await self.redis.exists(f"{self._suppression_prefix}{fp}") > 0
