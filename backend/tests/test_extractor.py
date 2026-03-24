from app.graph_rag.extractor import extract_graph_entities
from app.models.enums import Language

SIMPLE_PYTHON = """
import os
import sys

def hello(name: str) -> str:
    return f"hello {name}"

def main() -> None:
    result = hello("world")
    print(result)

class Greeter:
    def greet(self, name: str) -> str:
        return hello(name)
"""


def test_extracts_function_nodes():
    nodes, _ = extract_graph_entities(SIMPLE_PYTHON, Language.PYTHON, "test.py")
    kinds = {n.kind for n in nodes}
    assert "function" in kinds
    func_names = {n.name for n in nodes if n.kind == "function"}
    assert "hello" in func_names
    assert "main" in func_names


def test_extracts_class_nodes():
    nodes, _ = extract_graph_entities(SIMPLE_PYTHON, Language.PYTHON, "test.py")
    class_nodes = [n for n in nodes if n.kind == "class"]
    assert len(class_nodes) == 1
    assert class_nodes[0].name == "Greeter"


def test_extracts_module_node():
    nodes, _ = extract_graph_entities(SIMPLE_PYTHON, Language.PYTHON, "test.py")
    module_nodes = [n for n in nodes if n.kind == "module" and n.file_path == "test.py"]
    assert len(module_nodes) == 1


def test_extracts_contains_edges():
    _, edges = extract_graph_entities(SIMPLE_PYTHON, Language.PYTHON, "test.py")
    contains = [e for e in edges if e.relationship == "CONTAINS"]
    assert len(contains) >= 2  # module contains functions and class


def test_extracts_import_edges():
    _, edges = extract_graph_entities(SIMPLE_PYTHON, Language.PYTHON, "test.py")
    imports = [e for e in edges if e.relationship == "IMPORTS"]
    assert len(imports) >= 1


def test_extracts_call_edges():
    _, edges = extract_graph_entities(SIMPLE_PYTHON, Language.PYTHON, "test.py")
    calls = [e for e in edges if e.relationship == "CALLS"]
    callee_names = [e.metadata.get("callee_name") for e in calls]
    assert "hello" in callee_names


def test_empty_code_returns_module_only():
    nodes, edges = extract_graph_entities("", Language.PYTHON, "empty.py")
    assert any(n.kind == "module" for n in nodes)
    # No functions/classes
    assert not any(n.kind == "function" for n in nodes)
