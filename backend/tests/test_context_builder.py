from unittest.mock import AsyncMock, MagicMock

import pytest

from app.graph_rag.context_builder import build_context
from app.graph_rag.models import CallerInfo, CodebaseContext
from app.models.enums import Language

PYTHON_CODE = """
def process(data):
    return transform(data)

def transform(data):
    return data.upper()
"""


@pytest.mark.asyncio
async def test_returns_empty_when_store_none():
    result = await build_context(PYTHON_CODE, Language.PYTHON, "test.py", None)
    assert result == ""


@pytest.mark.asyncio
async def test_returns_empty_when_file_path_none():
    mock_store = MagicMock()
    mock_store.is_connected = True
    result = await build_context(PYTHON_CODE, Language.PYTHON, None, mock_store)
    assert result == ""


@pytest.mark.asyncio
async def test_returns_empty_when_disconnected():
    mock_store = MagicMock()
    mock_store.is_connected = False
    result = await build_context(PYTHON_CODE, Language.PYTHON, "test.py", mock_store)
    assert result == ""


@pytest.mark.asyncio
async def test_formats_context_with_callers():
    from app.graph_rag.store import GraphStore

    mock_store = MagicMock(spec=GraphStore)
    mock_store.is_connected = True
    mock_store.query_context = AsyncMock(
        return_value=CodebaseContext(
            queried_names=["process"],
            callers=[CallerInfo(name="run_pipeline", file_path="pipeline.py", kind="function")],
            callees=[],
            siblings=["transform"],
            imports=["os"],
            parent_class=None,
        )
    )

    result = await build_context(PYTHON_CODE, Language.PYTHON, "test.py", mock_store)

    assert "run_pipeline" in result
    assert "transform" in result
    assert "os" in result
