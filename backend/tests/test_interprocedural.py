"""Unit tests for the interprocedural taint tracker and call graph builder.

Tests cover:
- Call graph extraction for Python functions
- Cross-function taint propagation (callee returns tainted data, caller sinks it)
- MAX_CROSS_FILE_DEPTH file limit
- Sanitizer in the caller blocks propagation
- Multi-file cross-function flows
- No false positives when code is clean
"""

from __future__ import annotations

from app.dataflow.call_graph import (
    MAX_CROSS_FILE_DEPTH,
    CallGraph,
    build_call_graph,
)
from app.dataflow.interprocedural import InterProceduralTaintTracker
from app.dataflow.registry import sanitizer_registry, sink_registry, source_registry
from app.dataflow.schemas import SinkKind, SourceKind
from app.models.enums import Language


def _inter_tracker(lang: Language = Language.PYTHON) -> InterProceduralTaintTracker:
    return InterProceduralTaintTracker(source_registry, sink_registry, sanitizer_registry, lang)


# ─────────────────────────────────────────────────────────────────────────────
# Call graph extraction
# ─────────────────────────────────────────────────────────────────────────────


def test_call_graph_extracts_python_functions() -> None:
    code = """\
def fetch_input():
    data = request.args.get('q')
    return data

def process(val):
    result = eval(val)
    return result
"""
    cg = build_call_graph({"app.py": code}, Language.PYTHON)
    assert "fetch_input" in cg.functions
    assert "process" in cg.functions
    assert cg.functions["fetch_input"].params == []
    assert cg.functions["process"].params == ["val"]


def test_call_graph_records_call_sites() -> None:
    code = """\
def get_data():
    return request.args.get('x')

def handler():
    data = get_data()
    eval(data)
"""
    cg = build_call_graph({"app.py": code}, Language.PYTHON)
    callees = [cs.callee for cs in cg.callees_of("handler")]
    assert "get_data" in callees


def test_call_graph_tracks_return_lines() -> None:
    code = """\
def source_fn():
    val = request.args.get('input')
    return val
"""
    cg = build_call_graph({"app.py": code}, Language.PYTHON)
    func = cg.functions["source_fn"]
    assert any("val" in ret for ret in func.return_lines)


def test_call_graph_files_analyzed() -> None:
    files = {"a.py": "def f():\n    pass\n", "b.py": "def g():\n    pass\n"}
    cg = build_call_graph(files, Language.PYTHON)
    assert len(cg.files_analyzed) == 2


# ─────────────────────────────────────────────────────────────────────────────
# Cross-function taint propagation
# ─────────────────────────────────────────────────────────────────────────────


def test_cross_function_taint_source_to_sink() -> None:
    """Function A returns tainted data; function B calls A and passes result to sink."""
    code = """\
def get_user_input():
    data = request.args.get('cmd')
    return data

def handler():
    cmd = get_user_input()
    os.system(cmd)
"""
    tracker = _inter_tracker()
    candidates = tracker.analyze({"app.py": code})

    # Should detect the cross-function flow: request.args.get -> os.system
    # We expect at least one candidate with shell_exec sink
    shell_candidates = [c for c in candidates if c.sink.kind == SinkKind.SHELL_EXEC]
    assert len(shell_candidates) >= 1, (
        f"Expected cross-function taint flow to os.system, got {len(shell_candidates)} candidates"
    )


def test_cross_function_sql_injection() -> None:
    """Tainted input flows through a helper function into a SQL query."""
    code = """\
def read_param():
    name = request.args.get('name')
    return name

def search():
    username = read_param()
    cursor.execute("SELECT * FROM users WHERE name = " + username)
"""
    tracker = _inter_tracker()
    candidates = tracker.analyze({"app.py": code})
    sql_candidates = [c for c in candidates if c.sink.kind == SinkKind.SQL_QUERY]
    assert len(sql_candidates) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Sanitizer blocks propagation
# ─────────────────────────────────────────────────────────────────────────────


def test_sanitizer_in_caller_blocks_propagation() -> None:
    """If the caller sanitizes the return value before the sink, no candidate."""
    code = """\
def get_user_input():
    data = request.args.get('cmd')
    return data

def handler():
    cmd = get_user_input()
    safe = shlex.quote(cmd)
    os.system(safe)
"""
    tracker = _inter_tracker()
    candidates = tracker.analyze({"app.py": code})

    # The intra-procedural pass on handler() may not find a cross-function
    # candidate because shlex.quote sanitizes before os.system.
    # The cross-function pass should also respect sanitizers.
    cross_shell = [
        c for c in candidates
        if c.sink.kind == SinkKind.SHELL_EXEC
        and c.function_name == "handler"
    ]
    # shlex.quote is a sanitizer, so no exploitable path through handler
    assert len(cross_shell) == 0, (
        "Sanitizer in caller should block cross-function taint propagation"
    )


# ─────────────────────────────────────────────────────────────────────────────
# MAX_CROSS_FILE_DEPTH limit
# ─────────────────────────────────────────────────────────────────────────────


def test_max_cross_file_depth_caps_files() -> None:
    """Only MAX_CROSS_FILE_DEPTH files should be analyzed."""
    files = {f"file_{i}.py": f"def func_{i}():\n    pass\n" for i in range(10)}
    cg = build_call_graph(files, Language.PYTHON)
    assert len(cg.files_analyzed) <= MAX_CROSS_FILE_DEPTH


# ─────────────────────────────────────────────────────────────────────────────
# Clean code: no false positives
# ─────────────────────────────────────────────────────────────────────────────


def test_no_candidates_for_clean_code() -> None:
    """Functions that don't involve taint sources should produce no candidates."""
    code = """\
def add(a, b):
    return a + b

def main():
    result = add(1, 2)
    print(result)
"""
    tracker = _inter_tracker()
    candidates = tracker.analyze({"app.py": code})
    assert len(candidates) == 0


def test_no_cross_function_when_no_call_sites() -> None:
    """Tainted function that is never called produces only intra candidates."""
    code = """\
def dangerous():
    data = request.args.get('x')
    eval(data)

def safe():
    print("hello")
"""
    tracker = _inter_tracker()
    candidates = tracker.analyze({"app.py": code})
    # Only intra-procedural candidates from dangerous(), nothing cross-function
    assert all(c.function_name == "dangerous" for c in candidates)


# ─────────────────────────────────────────────────────────────────────────────
# Multi-file analysis
# ─────────────────────────────────────────────────────────────────────────────


def test_multi_file_taint_flow() -> None:
    """Source in file A, sink in file B via function call."""
    file_a = """\
def get_input():
    val = request.args.get('payload')
    return val
"""
    file_b = """\
def execute():
    payload = get_input()
    eval(payload)
"""
    tracker = _inter_tracker()
    candidates = tracker.analyze({"a.py": file_a, "b.py": file_b})
    code_exec = [c for c in candidates if c.sink.kind == SinkKind.CODE_EXEC]
    assert len(code_exec) >= 1, "Cross-file taint should be detected"


# ─────────────────────────────────────────────────────────────────────────────
# Candidate metadata
# ─────────────────────────────────────────────────────────────────────────────


def test_cross_function_candidate_has_hops() -> None:
    """Cross-function candidates should include hops from the callee."""
    code = """\
def get_user_input():
    data = request.args.get('cmd')
    return data

def handler():
    cmd = get_user_input()
    os.system(cmd)
"""
    tracker = _inter_tracker()
    candidates = tracker.analyze({"app.py": code})
    shell = [c for c in candidates if c.sink.kind == SinkKind.SHELL_EXEC]
    if shell:
        # Cross-function candidates should have multiple hops
        assert len(shell[0].hops) >= 1
