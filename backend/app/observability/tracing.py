from __future__ import annotations

from typing import Any

import structlog

from app.config import settings

logger = structlog.get_logger()

_langfuse_client: Any = None


def _get_langfuse_client() -> Any:
    """Lazily initialize the Langfuse client."""
    global _langfuse_client
    if _langfuse_client is None and settings.langfuse_enabled:
        try:
            from langfuse import Langfuse

            _langfuse_client = Langfuse(
                public_key=settings.langfuse_public_key,
                secret_key=settings.langfuse_secret_key,
                host=settings.langfuse_host,
            )
        except Exception as e:
            logger.warning("failed to initialize langfuse client", error=str(e))
    return _langfuse_client


def create_langfuse_handler(
    trace_id: str,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Any | None:
    """Return a Langfuse CallbackHandler for LangChain/LangGraph tracing.

    Returns None when Langfuse is disabled or initialization fails.
    The caller should filter None values from callback lists.
    """
    if not settings.langfuse_enabled:
        return None

    try:
        from langfuse.callback import CallbackHandler

        return CallbackHandler(
            public_key=settings.langfuse_public_key,
            secret_key=settings.langfuse_secret_key,
            host=settings.langfuse_host,
            trace_id=trace_id,
            session_id=session_id,
            metadata=metadata or {},
        )
    except Exception as e:
        logger.warning("failed to create langfuse handler", trace_id=trace_id, error=str(e))
        return None


def flush_langfuse() -> None:
    """Flush pending Langfuse events. Call on application shutdown."""
    client = _get_langfuse_client()
    if client is not None:
        try:
            client.flush()
            logger.info("langfuse flushed")
        except Exception as e:
            logger.warning("langfuse flush failed", error=str(e))
