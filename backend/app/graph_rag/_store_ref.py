"""Module-level singleton reference to the shared GraphStore instance.

Set during application startup in main.py lifespan.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.graph_rag.store import GraphStore

store: GraphStore | None = None
