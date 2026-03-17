from app.models.enums import Language
from app.parsers.tree_sitter_parser import parse_code


def test_parse_python_functions(python_good_code: str) -> None:
    structure = parse_code(python_good_code, Language.PYTHON)
    # 2 top-level functions + 3 class methods
    assert structure.metrics.num_functions == 5
    func_names = [f.name for f in structure.functions]
    assert "calculate_area" in func_names
    assert "fibonacci" in func_names
    assert "__init__" in func_names


def test_parse_python_classes(python_good_code: str) -> None:
    structure = parse_code(python_good_code, Language.PYTHON)
    assert structure.metrics.num_classes == 1
    assert structure.classes[0].name == "Shape"
    assert structure.classes[0].method_count == 3


def test_parse_python_imports(python_good_code: str) -> None:
    structure = parse_code(python_good_code, Language.PYTHON)
    assert structure.metrics.import_count == 2


def test_parse_python_docstrings(python_good_code: str) -> None:
    structure = parse_code(python_good_code, Language.PYTHON)
    for func in structure.functions:
        assert func.has_docstring, f"{func.name} should have a docstring"
    assert structure.classes[0].has_docstring


def test_parse_python_bad_complexity(python_bad_code: str) -> None:
    structure = parse_code(python_bad_code, Language.PYTHON)
    assert structure.metrics.cyclomatic_complexity > 5
    assert structure.metrics.max_nesting_depth >= 4


def test_parse_python_bad_no_docstrings(python_bad_code: str) -> None:
    structure = parse_code(python_bad_code, Language.PYTHON)
    for func in structure.functions:
        assert not func.has_docstring, f"{func.name} should not have a docstring"


def test_parse_javascript(javascript_bad_code: str) -> None:
    structure = parse_code(javascript_bad_code, Language.JAVASCRIPT)
    assert structure.metrics.num_functions >= 2
    assert structure.metrics.num_classes >= 1
    assert structure.metrics.max_nesting_depth >= 3


def test_parse_empty_code() -> None:
    structure = parse_code("", Language.PYTHON)
    assert structure.metrics.lines_of_code == 0
    assert structure.metrics.num_functions == 0


def test_parse_unsupported_language() -> None:
    structure = parse_code("package main", Language.GO)
    assert structure.metrics.num_functions == 0
    assert structure.metrics.cyclomatic_complexity == 1
