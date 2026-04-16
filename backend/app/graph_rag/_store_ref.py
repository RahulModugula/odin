"""Module-level singleton references to shared store instances.

Set during application startup in main.py lifespan.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.graph_rag.store import GraphStore
    from app.graph_rag.vector_store import VectorStore

store: GraphStore | None = None
vector_store: VectorStore | None = None
