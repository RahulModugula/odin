from __future__ import annotations

import hashlib

from app.graph_rag.models import GraphEdge, GraphNode
from app.models.enums import Language
from app.parsers.languages import get_language
from app.parsers.tree_sitter_parser import parse_code

# Call expression node types per language
_CALL_NODES: dict[str, str] = {
    "python": "call",
    "javascript": "call_expression",
}

# Argument lists holding the callee
_CALLEE_FIELD: dict[str, str] = {
    "python": "function",
    "javascript": "function",
}


def _node_id(kind: str, name: str, file_path: str) -> str:
    raw = f"{kind}:{name}:{file_path}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def extract_graph_entities(
    code: str,
    language: Language,
    file_path: str,
) -> tuple[list[GraphNode], list[GraphEdge]]:
    """Extract graph nodes and edges from source code using tree-sitter."""
    structure = parse_code(code, language)
    lang_key = language.value
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    # Module node
    module_id = _node_id("module", file_path, file_path)
    nodes.append(
        GraphNode(
            id=module_id,
            name=file_path,
            kind="module",
            file_path=file_path,
            language=lang_key,
        )
    )

    # Function nodes + CONTAINS edges
    for func in structure.functions:
        func_id = _node_id("function", func.name, file_path)
        nodes.append(
            GraphNode(
                id=func_id,
                name=func.name,
                kind="function",
                file_path=file_path,
                language=lang_key,
                line_start=func.line_start,
                line_end=func.line_end,
                metadata={"param_count": func.param_count, "has_docstring": func.has_docstring},
            )
        )
        edges.append(
            GraphEdge(
                source_id=module_id,
                target_id=func_id,
                relationship="CONTAINS",
            )
        )

    # Class nodes + CONTAINS edges
    for cls in structure.classes:
        cls_id = _node_id("class", cls.name, file_path)
        nodes.append(
            GraphNode(
                id=cls_id,
                name=cls.name,
                kind="class",
                file_path=file_path,
                language=lang_key,
                line_start=cls.line_start,
                line_end=cls.line_end,
                metadata={"method_count": cls.method_count, "has_docstring": cls.has_docstring},
            )
        )
        edges.append(
            GraphEdge(
                source_id=module_id,
                target_id=cls_id,
                relationship="CONTAINS",
            )
        )

    # Import edges: module IMPORTS target
    for imp in structure.imports:
        target_name = _parse_import_name(imp, lang_key)
        if target_name:
            target_id = _node_id("module", target_name, target_name)
            # Ensure target node exists (stub)
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

    # Call edges: extract call expressions from the AST
    call_edges = _extract_call_edges(code, language, file_path, lang_key)
    edges.extend(call_edges)

    return nodes, edges


def _parse_import_name(import_text: str, lang: str) -> str | None:
    """Extract the module name from an import statement string."""
    text = import_text.strip()
    if lang == "python":
        if text.startswith("from "):
            parts = text.split()
            return parts[1] if len(parts) >= 2 else None
        if text.startswith("import "):
            parts = text.split()
            return parts[1].split(".")[0] if len(parts) >= 2 else None
    elif lang == "javascript":
        # e.g. import { foo } from 'bar'
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
    """Walk the AST to find all call expressions and produce CALLS edges."""
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

    def walk(node: object) -> None:
        from tree_sitter import Node

        assert isinstance(node, Node)
        if node.type == call_node_type:
            callee = node.child_by_field_name(callee_field)
            if callee and callee.text:
                callee_name = callee.text.decode("utf-8").split("(")[0].strip()
                # Strip attribute access (e.g. self.foo → foo)
                if "." in callee_name:
                    callee_name = callee_name.split(".")[-1]
                if callee_name:
                    target_id = _node_id("function", callee_name, file_path)
                    edges.append(
                        GraphEdge(
                            source_id=caller_id,
                            target_id=target_id,
                            relationship="CALLS",
                            metadata={"callee_name": callee_name},
                        )
                    )
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return edges
