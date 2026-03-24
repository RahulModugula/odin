import tree_sitter_javascript
import tree_sitter_python
from tree_sitter import Language

from app.models.enums import Language as LangEnum

_LANGUAGES: dict[str, Language] = {
    "python": Language(tree_sitter_python.language()),
    "javascript": Language(tree_sitter_javascript.language()),
}


def get_language(lang: LangEnum) -> Language | None:
    return _LANGUAGES.get(lang.value)


def supported_languages() -> list[str]:
    return list(_LANGUAGES.keys())
