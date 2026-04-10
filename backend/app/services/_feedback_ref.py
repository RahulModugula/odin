"""Module-level reference to the FeedbackService singleton.

Pattern mirrors app/graph_rag/_store_ref.py — allows the LangGraph nodes
(which cannot receive DI-injected dependencies) to access the service
without importing from the FastAPI application layer.

Set by app/main.py during lifespan startup:
    import app.services._feedback_ref as _fb_ref
    _fb_ref.service = feedback_service_instance
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.services.feedback import FeedbackService

service: FeedbackService | None = None
