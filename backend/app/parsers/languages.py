from __future__ import annotations

import tree_sitter_javascript
import tree_sitter_python
from tree_sitter import Language

from app.models.enums import Language as LangEnum

# TypeScript and Go are optional; fall back gracefully if not installed.
try:
    import tree_sitter_typescript  # type: ignore[import-untyped]

    _ts_language = Language(tree_sitter_typescript.language_typescript())
    _tsx_language = Language(tree_sitter_typescript.language_tsx())
except Exception:
    _ts_language = None  # type: ignore[assignment]
    _tsx_language = None  # type: ignore[assignment]

try:
    import tree_sitter_go  # type: ignore[import-untyped]

    _go_language = Language(tree_sitter_go.language())
except Exception:
    _go_language = None  # type: ignore[assignment]

_LANGUAGES: dict[str, Language] = {
    "python": Language(tree_sitter_python.language()),
    "javascript": Language(tree_sitter_javascript.language()),
}

if _ts_language is not None:
    _LANGUAGES["typescript"] = _ts_language

if _go_language is not None:
    _LANGUAGES["go"] = _go_language


def get_language(lang: LangEnum) -> Language | None:
    return _LANGUAGES.get(lang.value)


def supported_languages() -> list[str]:
    return list(_LANGUAGES.keys())
