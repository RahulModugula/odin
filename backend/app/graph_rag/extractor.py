from __future__ import annotations

import hashlib
import re

from app.graph_rag.models import GraphEdge, GraphNode
from app.models.enums import Language
from app.parsers.languages import get_language
from app.parsers.tree_sitter_parser import parse_code

_CALL_NODES: dict[str, str] = {
    "python": "call",
    "javascript": "call_expression",
}

_CALLEE_FIELD: dict[str, str] = {
    "python": "function",
    "javascript": "function",
}

_DECORATOR_NODES: dict[str, set[str]] = {
    "python": {"decorator"},
    "javascript": {"decorator"},
}

_TYPE_ANNOTATION_NODES: dict[str, set[str]] = {
    "python": {"type", "identifier", "attribute", "subscript", "binary_operator"},
    "javascript": {"type_annotation", "type_identifier"},
}


def _node_id(kind: str, name: str, file_path: str) -> str:
    raw = f"{kind}:{name}:{file_path}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _extract_signature_from_ast(node, code_bytes: bytes, lang_key: str) -> str | None:
    try:
        from tree_sitter import Node

        assert isinstance(node, Node)
    except (ImportError, AssertionError):
        return None

    if lang_key == "python":
        params_node = node.child_by_field_name("parameters")
        return_node = node.child_by_field_name("return_type")
        name_text = ""
        if node.child_by_field_name("name") and node.child_by_field_name("name").text:
            name_text = node.child_by_field_name("name").text.decode("utf-8")

        params_text = ""
        if params_node and params_node.text:
            params_text = params_node.text.decode("utf-8")

        return_text = ""
        if return_node and return_node.text:
            return_text = " -> " + return_node.text.decode("utf-8")

        if name_text:
            return f"{name_text}{params_text}{return_text}"
    return None


def _extract_decorators(node, lang_key: str) -> list[str]:
    decorators: list[str] = []
    try:
        from tree_sitter import Node

        assert isinstance(node, Node)
    except (ImportError, AssertionError):
        return decorators

    if lang_key != "python":
        return decorators

    for child in node.children:
        if child.type == "decorator":
            text = child.text.decode("utf-8") if child.text else ""
            if text:
                decorators.append(text)
    return decorators


def _extract_type_info(node, lang_key: str) -> tuple[list[str], str | None]:
    param_types: list[str] = []
    return_type: str | None = None

    try:
        from tree_sitter import Node

        assert isinstance(node, Node)
    except (ImportError, AssertionError):
        return param_types, return_type

    params_node = node.child_by_field_name("parameters")
    if params_node:
        for child in params_node.children:
            if child.type in ("typed_parameter", "typed_default_parameter"):
                type_node = child.child_by_field_name("type")
                if type_node and type_node.text:
                    param_types.append(type_node.text.decode("utf-8"))
                name_node = child.child_by_field_name("name")
                if name_node and name_node.text and not type_node:
                    pass

    return_node = node.child_by_field_name("return_type")
    if return_node and return_node.text:
        return_type = return_node.text.decode("utf-8")

    return param_types, return_type


def _extract_class_inheritance(node, lang_key: str) -> str | None:
    try:
        from tree_sitter import Node

        assert isinstance(node, Node)
    except (ImportError, AssertionError):
        return None

    if lang_key == "python":
        arg_list = node.child_by_field_name("superclasses")
        if arg_list and arg_list.children:
            first_parent = arg_list.children[0]
            if first_parent.text:
                return first_parent.text.decode("utf-8")
    elif lang_key in ("javascript", "typescript"):
        for child in node.children:
            if child.type == "class_heritage" and child.text:
                heritage_text = child.text.decode("utf-8")
                extends_match = re.search(r"extends\s+(\w+)", heritage_text)
                if extends_match:
                    return extends_match.group(1)
    return None


def _extract_method_overrides(
    class_node, class_name: str, parent_class: str, file_path: str, lang_key: str
) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    try:
        from tree_sitter import Node

        assert isinstance(class_node, Node)
    except (ImportError, AssertionError):
        return edges

    body = class_node.child_by_field_name("body")
    if not body:
        return edges

    func_types = {"function_definition", "function_declaration", "method_definition"}
    for child in body.children:
        if child.type in func_types:
            name_node = child.child_by_field_name("name")
            if name_node and name_node.text:
                method_name = name_node.text.decode("utf-8")
                method_id = _node_id("function", method_name, file_path)
                parent_method_id = _node_id("function", method_name, f"parent:{parent_class}")
                edges.append(
                    GraphEdge(
                        source_id=method_id,
                        target_id=parent_method_id,
                        relationship="OVERRIDES",
                        metadata={"class": class_name, "parent_class": parent_class},
                    )
                )
    return edges


def _extract_docstring(node, lang_key: str) -> str | None:
    if lang_key != "python":
        return None
    try:
        from tree_sitter import Node

        assert isinstance(node, Node)
    except (ImportError, AssertionError):
        return None

    body = node.child_by_field_name("body")
    if body and body.children:
        first_stmt = body.children[0]
        if first_stmt.type == "expression_statement" and first_stmt.children:
            expr = first_stmt.children[0]
            if expr.type == "string" and expr.text:
                text = expr.text.decode("utf-8")
                return text.strip("\"'").strip()
    return None


def extract_graph_entities(
    code: str,
    language: Language,
    file_path: str,
) -> tuple[list[GraphNode], list[GraphEdge]]:
    structure = parse_code(code, language)
    lang_key = language.value
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    source_hash = hashlib.sha256(code.encode()).hexdigest()[:16]

    module_id = _node_id("module", file_path, file_path)
    nodes.append(
        GraphNode(
            id=module_id,
            name=file_path,
            kind="module",
            file_path=file_path,
            language=lang_key,
            source_hash=source_hash,
        )
    )

    code_lines = code.splitlines()

    ts_tree = None
    ts_root = None
    try:
        ts_lang = get_language(language)
        if ts_lang is not None:
            from tree_sitter import Parser

            parser = Parser(ts_lang)
            ts_tree = parser.parse(code.encode("utf-8"))
            ts_root = ts_tree.root_node
    except Exception:
        pass

    func_nodes_map: dict[str, object] = {}
    class_nodes_map: dict[str, object] = {}

    if ts_root is not None:
        try:
            from tree_sitter import Node

            func_types = {
                "python": {"function_definition"},
                "javascript": {"function_declaration", "arrow_function", "method_definition"},
                "typescript": {
                    "function_declaration",
                    "arrow_function",
                    "method_definition",
                    "function_signature",
                },
                "go": {"function_declaration", "method_declaration"},
            }.get(lang_key, set())

            class_types = {
                "python": {"class_definition"},
                "javascript": {"class_declaration"},
                "typescript": {"class_declaration"},
                "go": {"type_declaration"},
            }.get(lang_key, set())

            def walk_ast(node: Node) -> None:
                if node.type in class_types:
                    name_node = node.child_by_field_name("name")
                    if name_node and name_node.text:
                        cls_name = name_node.text.decode("utf-8")
                        cls_id = _node_id("class", cls_name, file_path)
                        ls = node.start_point[0] + 1
                        le = node.end_point[0] + 1

                        parent_class = _extract_class_inheritance(node, lang_key)
                        cls_decorators = _extract_decorators(node, lang_key)

                        nodes.append(
                            GraphNode(
                                id=cls_id,
                                name=cls_name,
                                kind="class",
                                file_path=file_path,
                                language=lang_key,
                                line_start=ls,
                                line_end=le,
                                decorators=cls_decorators,
                                metadata={"parent_class": parent_class} if parent_class else {},
                                source_hash=source_hash,
                            )
                        )
                        edges.append(
                            GraphEdge(
                                source_id=module_id,
                                target_id=cls_id,
                                relationship="CONTAINS",
                            )
                        )

                        if parent_class:
                            parent_id = _node_id("class", parent_class, f"parent:{parent_class}")
                            nodes.append(
                                GraphNode(
                                    id=parent_id,
                                    name=parent_class,
                                    kind="class",
                                    file_path=f"external:{parent_class}",
                                    language=lang_key,
                                )
                            )
                            edges.append(
                                GraphEdge(
                                    source_id=cls_id,
                                    target_id=parent_id,
                                    relationship="INHERITS",
                                )
                            )

                            override_edges = _extract_method_overrides(
                                node, cls_name, parent_class, file_path, lang_key
                            )
                            edges.extend(override_edges)

                        class_nodes_map[cls_name] = node

                elif node.type in func_types:
                    name_node = node.child_by_field_name("name")
                    name = ""
                    if name_node and name_node.text:
                        name = name_node.text.decode("utf-8")
                    if not name:
                        for child in node.children:
                            if child.type == "property_identifier" and child.text:
                                name = child.text.decode("utf-8")
                                break
                    if not name:
                        name = "<anonymous>"

                    func_id = _node_id("function", name, file_path)
                    ls = node.start_point[0] + 1
                    le = node.end_point[0] + 1

                    sig = _extract_signature_from_ast(node, code.encode("utf-8"), lang_key)
                    if sig is None and ls <= len(code_lines) and le <= len(code_lines):
                        sig = "\n".join(code_lines[ls - 1 : le])

                    func_decorators = _extract_decorators(node, lang_key)
                    param_types, return_type = _extract_type_info(node, lang_key)
                    docstring = _extract_docstring(node, lang_key)

                    parent_cls = None
                    for cls_name, cls_node in class_nodes_map.items():
                        try:
                            import tree_sitter as _ts

                            assert isinstance(cls_node, _ts.Node)  # noqa: N814
                            cls_body = cls_node.child_by_field_name("body")
                            if cls_body:
                                for child in cls_body.children:
                                    if child.id == node.id:
                                        parent_cls = cls_name
                                        break
                        except (ImportError, AssertionError):
                            pass
                        if parent_cls:
                            break

                    func_nodes_map[name] = node

                    nodes.append(
                        GraphNode(
                            id=func_id,
                            name=name,
                            kind="function",
                            file_path=file_path,
                            language=lang_key,
                            line_start=ls,
                            line_end=le,
                            signature=sig,
                            decorators=func_decorators,
                            param_types=param_types,
                            return_type=return_type,
                            docstring=docstring,
                            parent_class_name=parent_cls,
                            source_hash=source_hash,
                            metadata={
                                "param_count": structure.functions[0].param_count
                                if structure.functions
                                else 0
                            },
                        )
                    )
                    edges.append(
                        GraphEdge(
                            source_id=module_id,
                            target_id=func_id,
                            relationship="CONTAINS",
                        )
                    )

                    for dec_text in func_decorators:
                        dec_name = re.match(r"@(\w+)", dec_text)
                        if dec_name:
                            dec_id = _node_id("decorator", dec_name.group(1), file_path)
                            nodes.append(
                                GraphNode(
                                    id=dec_id,
                                    name=dec_name.group(1),
                                    kind="decorator",
                                    file_path=file_path,
                                    language=lang_key,
                                    metadata={"full_text": dec_text},
                                )
                            )
                            edges.append(
                                GraphEdge(
                                    source_id=func_id,
                                    target_id=dec_id,
                                    relationship="HAS_DECORATOR",
                                    metadata={"decorator_text": dec_text},
                                )
                            )

                    if param_types:
                        for pt in param_types:
                            type_id = _node_id("type", pt, file_path)
                            nodes.append(
                                GraphNode(
                                    id=type_id,
                                    name=pt,
                                    kind="type",
                                    file_path=file_path,
                                    language=lang_key,
                                )
                            )
                            edges.append(
                                GraphEdge(
                                    source_id=func_id,
                                    target_id=type_id,
                                    relationship="USES_TYPE",
                                )
                            )

                    if return_type:
                        ret_type_id = _node_id("type", return_type, file_path)
                        nodes.append(
                            GraphNode(
                                id=ret_type_id,
                                name=return_type,
                                kind="type",
                                file_path=file_path,
                                language=lang_key,
                            )
                        )
                        edges.append(
                            GraphEdge(
                                source_id=func_id,
                                target_id=ret_type_id,
                                relationship="USES_TYPE",
                            )
                        )

                for child in node.children:
                    walk_ast(child)

            walk_ast(ts_root)
        except Exception:
            pass

    if not func_nodes_map:
        for func in structure.functions:
            if func.name == "<anonymous>":
                continue
            func_id = _node_id("function", func.name, file_path)
            if not any(n.id == func_id for n in nodes):
                ls = func.line_start
                le = func.line_end
                sig = "\n".join(code_lines[ls - 1 : le]) if ls <= len(code_lines) else None
                nodes.append(
                    GraphNode(
                        id=func_id,
                        name=func.name,
                        kind="function",
                        file_path=file_path,
                        language=lang_key,
                        line_start=ls,
                        line_end=le,
                        signature=sig,
                        source_hash=source_hash,
                        metadata={
                            "param_count": func.param_count,
                            "has_docstring": func.has_docstring,
                        },
                    )
                )
                edges.append(
                    GraphEdge(
                        source_id=module_id,
                        target_id=func_id,
                        relationship="CONTAINS",
                    )
                )

    if not class_nodes_map:
        for cls in structure.classes:
            cls_id = _node_id("class", cls.name, file_path)
            if not any(n.id == cls_id for n in nodes):
                nodes.append(
                    GraphNode(
                        id=cls_id,
                        name=cls.name,
                        kind="class",
                        file_path=file_path,
                        language=lang_key,
                        line_start=cls.line_start,
                        line_end=cls.line_end,
                        source_hash=source_hash,
                        metadata={
                            "method_count": cls.method_count,
                            "has_docstring": cls.has_docstring,
                        },
                    )
                )
                edges.append(
                    GraphEdge(
                        source_id=module_id,
                        target_id=cls_id,
                        relationship="CONTAINS",
                    )
                )

    for imp in structure.imports:
        target_name = _parse_import_name(imp, lang_key)
        if target_name:
            target_id = _node_id("module", target_name, target_name)
            nodes.append(
                GraphNode(
                    id=target_id,
                    name=target_name,
                    kind="module",
                    file_path=target_name,
                    language=lang_key,
                )
            )
            edges.append(
                GraphEdge(
                    source_id=module_id,
                    target_id=target_id,
                    relationship="IMPORTS",
                )
            )

    call_edges = _extract_call_edges(code, language, file_path, lang_key)
    edges.extend(call_edges)

    return nodes, edges


def _parse_import_name(import_text: str, lang: str) -> str | None:
    text = import_text.strip()
    if lang == "python":
        if text.startswith("from "):
            parts = text.split()
            return parts[1] if len(parts) >= 2 else None
        if text.startswith("import "):
            parts = text.split()
            return parts[1].split(".")[0] if len(parts) >= 2 else None
    elif lang == "javascript":
        if "from" in text:
            raw = text.split("from")[-1].strip().strip("'\"").strip(";")
            return raw or None
    return None


def _extract_call_edges(
    code: str,
    language: Language,
    file_path: str,
    lang_key: str,
) -> list[GraphEdge]:
    ts_lang = get_language(language)
    if ts_lang is None:
        return []

    from tree_sitter import Parser

    call_node_type = _CALL_NODES.get(lang_key)
    callee_field = _CALLEE_FIELD.get(lang_key, "function")
    if not call_node_type:
        return []

    parser = Parser(ts_lang)
    tree = parser.parse(code.encode("utf-8"))
    edges: list[GraphEdge] = []
    caller_id = _node_id("module", file_path, file_path)

    def find_enclosing_function(node: object) -> str | None:
        try:
            from tree_sitter import Node

            assert isinstance(node, Node)
            parent = node.parent
            func_types = {
                "python": {"function_definition"},
                "javascript": {"function_declaration", "arrow_function", "method_definition"},
                "typescript": {
                    "function_declaration",
                    "arrow_function",
                    "method_definition",
                },
                "go": {"function_declaration", "method_declaration"},
            }.get(lang_key, set())

            while parent is not None:
                if parent.type in func_types:
                    name_node = parent.child_by_field_name("name")
                    if name_node and name_node.text:
                        return name_node.text.decode("utf-8")
                parent = parent.parent
        except (ImportError, AssertionError):
            pass
        return None

    def walk(node: object) -> None:
        from tree_sitter import Node

        assert isinstance(node, Node)
        if node.type == call_node_type:
            callee = node.child_by_field_name(callee_field)
            if callee and callee.text:
                callee_name = callee.text.decode("utf-8").split("(")[0].strip()
                if "." in callee_name:
                    callee_name = callee_name.split(".")[-1]
                if callee_name:
                    target_id = _node_id("function", callee_name, file_path)

                    enclosing = find_enclosing_function(node)
                    if enclosing:
                        source_id = _node_id("function", enclosing, file_path)
                    else:
                        source_id = caller_id

                    edges.append(
                        GraphEdge(
                            source_id=source_id,
                            target_id=target_id,
                            relationship="CALLS",
                            metadata={"callee_name": callee_name, "caller_function": enclosing},
                        )
                    )
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return edges
