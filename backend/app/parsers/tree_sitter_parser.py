from tree_sitter import Node, Parser

from app.models.enums import Language
from app.models.schemas import (
    ClassInfo,
    CodeMetrics,
    CodeStructure,
    FunctionInfo,
)
from app.parsers.languages import get_language

# Node types that increase cyclomatic complexity
_COMPLEXITY_NODES: dict[str, set[str]] = {
    "python": {
        "if_statement",
        "elif_clause",
        "for_statement",
        "while_statement",
        "except_clause",
        "with_statement",
        "boolean_operator",
        "conditional_expression",
        "list_comprehension",
    },
    "javascript": {
        "if_statement",
        "for_statement",
        "for_in_statement",
        "while_statement",
        "do_statement",
        "catch_clause",
        "ternary_expression",
        "binary_expression",  # for && and ||
        "switch_case",
    },
}

# Function definition node types per language
_FUNCTION_NODES: dict[str, set[str]] = {
    "python": {"function_definition"},
    "javascript": {"function_declaration", "arrow_function", "method_definition"},
}

_CLASS_NODES: dict[str, set[str]] = {
    "python": {"class_definition"},
    "javascript": {"class_declaration"},
}

_IMPORT_NODES: dict[str, set[str]] = {
    "python": {"import_statement", "import_from_statement"},
    "javascript": {"import_statement"},
}

_COMMENT_NODES: dict[str, set[str]] = {
    "python": {"comment"},
    "javascript": {"comment"},
}


def parse_code(code: str, language: Language) -> CodeStructure:
    ts_lang = get_language(language)
    if ts_lang is None:
        return _empty_structure(code)

    parser = Parser(ts_lang)
    tree = parser.parse(code.encode("utf-8"))
    root = tree.root_node

    lang_key = language.value
    functions = _extract_functions(root, lang_key)
    classes = _extract_classes(root, lang_key)
    imports = _extract_imports(root, lang_key)
    complexity = _calculate_complexity(root, lang_key)
    max_depth = _calculate_nesting_depth(root, lang_key)
    comment_ratio = _calculate_comment_ratio(root, lang_key)

    lines = code.count("\n") + 1 if code.strip() else 0
    func_lengths = [f.body_length for f in functions]
    avg_func_len = sum(func_lengths) / len(func_lengths) if func_lengths else 0.0
    max_func_len = max(func_lengths) if func_lengths else 0

    metrics = CodeMetrics(
        lines_of_code=lines,
        num_functions=len(functions),
        num_classes=len(classes),
        avg_function_length=round(avg_func_len, 1),
        max_function_length=max_func_len,
        max_nesting_depth=max_depth,
        cyclomatic_complexity=complexity,
        comment_ratio=round(comment_ratio, 3),
        import_count=len(imports),
    )

    return CodeStructure(
        functions=functions,
        classes=classes,
        imports=imports,
        metrics=metrics,
    )


def _extract_functions(root: Node, lang: str) -> list[FunctionInfo]:
    func_types = _FUNCTION_NODES.get(lang, set())
    functions: list[FunctionInfo] = []

    def walk(node: Node) -> None:
        if node.type in func_types:
            name = _get_child_text(node, "name") or _get_child_text(node, "property_identifier")
            if not name:
                name = "<anonymous>"
            params = _count_params(node, lang)
            line_start = node.start_point[0] + 1
            line_end = node.end_point[0] + 1
            body_length = line_end - line_start + 1
            has_doc = _has_docstring(node, lang)

            functions.append(
                FunctionInfo(
                    name=name,
                    line_start=line_start,
                    line_end=line_end,
                    param_count=params,
                    body_length=body_length,
                    has_docstring=has_doc,
                )
            )

        for child in node.children:
            walk(child)

    walk(root)
    return functions


def _extract_classes(root: Node, lang: str) -> list[ClassInfo]:
    class_types = _CLASS_NODES.get(lang, set())
    classes: list[ClassInfo] = []

    def walk(node: Node) -> None:
        if node.type in class_types:
            name = _get_child_text(node, "name")
            if not name:
                name = "<unknown>"
            line_start = node.start_point[0] + 1
            line_end = node.end_point[0] + 1
            method_count = _count_methods(node, lang)
            has_doc = _has_docstring(node, lang)

            classes.append(
                ClassInfo(
                    name=name,
                    line_start=line_start,
                    line_end=line_end,
                    method_count=method_count,
                    has_docstring=has_doc,
                )
            )

        for child in node.children:
            walk(child)

    walk(root)
    return classes


def _extract_imports(root: Node, lang: str) -> list[str]:
    import_types = _IMPORT_NODES.get(lang, set())
    imports: list[str] = []

    def walk(node: Node) -> None:
        if node.type in import_types:
            text = node.text
            if text:
                imports.append(text.decode("utf-8"))
        for child in node.children:
            walk(child)

    walk(root)
    return imports


def _calculate_complexity(root: Node, lang: str) -> int:
    complexity_types = _COMPLEXITY_NODES.get(lang, set())
    complexity = 1  # base complexity

    def walk(node: Node) -> None:
        nonlocal complexity
        if node.type in complexity_types:
            if lang == "javascript" and node.type == "binary_expression":
                op = _get_child_text(node, "operator")
                if op in ("&&", "||"):
                    complexity += 1
            else:
                complexity += 1
        for child in node.children:
            walk(child)

    walk(root)
    return complexity


def _calculate_nesting_depth(root: Node, lang: str) -> int:
    nesting_types = {
        "python": {
            "if_statement",
            "for_statement",
            "while_statement",
            "with_statement",
            "try_statement",
            "function_definition",
            "class_definition",
        },
        "javascript": {
            "if_statement",
            "for_statement",
            "for_in_statement",
            "while_statement",
            "do_statement",
            "try_statement",
            "function_declaration",
            "arrow_function",
            "class_declaration",
        },
    }
    types = nesting_types.get(lang, set())
    max_depth = 0

    def walk(node: Node, depth: int) -> None:
        nonlocal max_depth
        current_depth = depth
        if node.type in types:
            current_depth = depth + 1
            max_depth = max(max_depth, current_depth)
        for child in node.children:
            walk(child, current_depth)

    walk(root, 0)
    return max_depth


def _calculate_comment_ratio(root: Node, lang: str) -> float:
    comment_types = _COMMENT_NODES.get(lang, set())
    total_nodes = 0
    comment_nodes = 0

    def walk(node: Node) -> None:
        nonlocal total_nodes, comment_nodes
        total_nodes += 1
        if node.type in comment_types:
            comment_nodes += 1
        for child in node.children:
            walk(child)

    walk(root)
    return comment_nodes / total_nodes if total_nodes > 0 else 0.0


def _get_child_text(node: Node, field_name: str) -> str | None:
    child = node.child_by_field_name(field_name)
    if child and child.text:
        return child.text.decode("utf-8")
    return None


def _count_params(node: Node, lang: str) -> int:
    if lang == "python":
        params_node = node.child_by_field_name("parameters")
    else:
        params_node = node.child_by_field_name("parameters") or node.child_by_field_name(
            "parameter"
        )

    if not params_node:
        return 0

    count = 0
    for child in params_node.children:
        if child.type in (
            "identifier",
            "typed_parameter",
            "default_parameter",
            "typed_default_parameter",
            "formal_parameters",
            "required_parameter",
            "optional_parameter",
        ):
            count += 1
    return count


def _count_methods(node: Node, lang: str) -> int:
    func_types = _FUNCTION_NODES.get(lang, set())
    count = 0
    body = node.child_by_field_name("body")
    if body:
        for child in body.children:
            if child.type in func_types:
                count += 1
    return count


def _has_docstring(node: Node, lang: str) -> bool:
    if lang == "python":
        body = node.child_by_field_name("body")
        if body and body.children:
            first_stmt = body.children[0]
            if first_stmt.type == "expression_statement" and first_stmt.children:
                return first_stmt.children[0].type == "string"
    return False


def _empty_structure(code: str) -> CodeStructure:
    lines = code.count("\n") + 1 if code.strip() else 0
    return CodeStructure(
        metrics=CodeMetrics(
            lines_of_code=lines,
            num_functions=0,
            num_classes=0,
            avg_function_length=0.0,
            max_function_length=0,
            max_nesting_depth=0,
            cyclomatic_complexity=1,
            comment_ratio=0.0,
            import_count=0,
        )
    )
