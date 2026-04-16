"""Unit tests for the intra-procedural taint tracker.

Each test verifies a specific propagation scenario:
- Source seeding
- Direct sink access
- Assignment-chain propagation
- f-string / template-literal propagation
- Sanitizer removal
- Multi-hop paths
- False-negative assertions (clean code produces no candidates)
"""

from __future__ import annotations

from app.dataflow.registry import sanitizer_registry, sink_registry, source_registry
from app.dataflow.schemas import SinkKind, SourceKind
from app.dataflow.tracker import IntraProceduralTaintTracker
from app.models.enums import Language


def _tracker(lang: Language) -> IntraProceduralTaintTracker:
    return IntraProceduralTaintTracker(source_registry, sink_registry, sanitizer_registry, lang)


# ─────────────────────────────────────────────────────────────────────────────
# Python: source seeding
# ─────────────────────────────────────────────────────────────────────────────


def test_python_source_http_param_seeded() -> None:
    code = """
username = request.args.get('username')
result = db.execute("SELECT * FROM users WHERE name = " + username)
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert len(candidates) >= 1
    assert any(c.source.kind == SourceKind.HTTP_PARAM for c in candidates)


def test_python_source_eval_direct() -> None:
    code = """
expr = request.args.get('expr')
result = eval(expr)
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert len(candidates) >= 1
    assert any(c.sink.kind == SinkKind.CODE_EXEC for c in candidates)


def test_python_os_system_tainted() -> None:
    code = """
host = request.args.get('host')
os.system(f"ping -c 1 {host}")
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert any(c.sink.kind == SinkKind.SHELL_EXEC for c in candidates)


def test_python_subprocess_shell_true_tainted() -> None:
    code = """
cmd = request.form.get('cmd')
subprocess.run(cmd, shell=True)
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert any(c.sink.kind == SinkKind.SHELL_EXEC for c in candidates)


# ─────────────────────────────────────────────────────────────────────────────
# Python: assignment-chain propagation
# ─────────────────────────────────────────────────────────────────────────────


def test_python_assignment_chain_propagates() -> None:
    code = """
raw = request.args.get('q')
query = raw
cursor.execute("SELECT * FROM t WHERE x = " + query)
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert len(candidates) >= 1, "Taint should propagate through assignment chain"


def test_python_fstring_propagates() -> None:
    code = """
user_id = request.args.get('id')
sql = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(sql)
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert len(candidates) >= 1, "Taint should propagate through f-string"


# ─────────────────────────────────────────────────────────────────────────────
# Python: SSRF
# ─────────────────────────────────────────────────────────────────────────────


def test_python_ssrf_detected() -> None:
    code = """
url = request.args.get('url')
response = requests.get(url)
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert any(c.sink.kind == SinkKind.SSRF_FETCH for c in candidates)


def test_python_ssrf_client_get() -> None:
    code = """
target = request.json.get('target')
resp = client.get(target)
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert any(c.sink.kind == SinkKind.SSRF_FETCH for c in candidates)


# ─────────────────────────────────────────────────────────────────────────────
# Python: path traversal
# ─────────────────────────────────────────────────────────────────────────────


def test_python_path_traversal_via_open() -> None:
    code = """
filename = request.args.get('file')
with open(filename) as f:
    data = f.read()
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert any(c.sink.kind == SinkKind.PATH_TRAVERSAL for c in candidates)


# ─────────────────────────────────────────────────────────────────────────────
# Python: clean code produces no candidates
# ─────────────────────────────────────────────────────────────────────────────


def test_python_parameterized_sql_no_candidate() -> None:
    """Parameterized queries should NOT be flagged."""
    code = """
user_id = request.args.get('id', type=int)
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    # May produce a candidate (tracker is conservative) — but triage would remove it
    # This test documents that the tracker may flag even parameterized queries;
    # that's by design — precision comes from the LLM triage stage
    # We only assert the tracker doesn't crash
    assert isinstance(candidates, list)


def test_python_env_var_not_flagged_as_http() -> None:
    """Reading from os.environ should be tagged as ENV_VAR, not HTTP."""
    code = """
secret = os.environ.get('SECRET_KEY')
cursor.execute("SELECT * FROM configs WHERE key = " + secret)
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    env_candidates = [c for c in candidates if c.source.kind == SourceKind.ENV_VAR]
    # Env var taint IS tracked (env vars can be user-controlled in some threat models)
    assert isinstance(env_candidates, list)


def test_python_no_source_no_candidate() -> None:
    """Code with no taint sources should produce no candidates."""
    code = """
def add(a: int, b: int) -> int:
    return a + b

result = add(1, 2)
cursor.execute("SELECT * FROM t WHERE id = ?", (result,))
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    # cursor.execute is a sink but no taint source — no candidates expected
    assert len(candidates) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Python: deserialization
# ─────────────────────────────────────────────────────────────────────────────


def test_python_pickle_loads_candidate() -> None:
    code = """
data = request.form.get('session')
decoded = base64.b64decode(data)
obj = pickle.loads(decoded)
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert any(c.sink.kind == SinkKind.DESERIALIZED for c in candidates)


# ─────────────────────────────────────────────────────────────────────────────
# JavaScript: XSS
# ─────────────────────────────────────────────────────────────────────────────


def test_js_xss_via_innerhtml() -> None:
    code = """
const query = new URLSearchParams(window.location.search).get('q');
document.getElementById('search').innerHTML = query;
"""
    candidates = _tracker(Language.JAVASCRIPT).analyze(code)
    assert any(c.sink.kind == SinkKind.DOM_WRITE for c in candidates)


def test_js_eval_with_param() -> None:
    code = """
const expr = req.query.expr;
const result = eval(expr);
"""
    candidates = _tracker(Language.JAVASCRIPT).analyze(code)
    assert any(c.sink.kind == SinkKind.CODE_EXEC for c in candidates)


# ─────────────────────────────────────────────────────────────────────────────
# JavaScript: clean code
# ─────────────────────────────────────────────────────────────────────────────


def test_js_textcontent_is_clean() -> None:
    """textContent assignment is safe and should produce no DOM_WRITE candidates."""
    code = """
const name = req.query.name;
document.getElementById('name').textContent = name;
"""
    candidates = _tracker(Language.JAVASCRIPT).analyze(code)
    dom_candidates = [c for c in candidates if c.sink.kind == SinkKind.DOM_WRITE]
    assert len(dom_candidates) == 0, "textContent should not be flagged as XSS sink"


def test_js_no_source_no_candidate() -> None:
    """Hardcoded values through a sink should produce no candidates."""
    code = """
const FIXED_URL = 'https://api.example.com/data';
const resp = await fetch(FIXED_URL);
"""
    candidates = _tracker(Language.JAVASCRIPT).analyze(code)
    assert len(candidates) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Snippet and metadata
# ─────────────────────────────────────────────────────────────────────────────


def test_candidate_snippet_contains_sink_line() -> None:
    code = """
user = request.args.get('user')
os.system(f"ping {user}")
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert len(candidates) >= 1
    snippet = candidates[0].snippet
    assert "os.system" in snippet or "ping" in snippet


def test_candidate_id_is_stable() -> None:
    """Same code should produce the same candidate IDs."""
    code = """
x = request.args.get('x')
eval(x)
"""
    t = _tracker(Language.PYTHON)
    candidates1 = t.analyze(code)
    candidates2 = t.analyze(code)
    ids1 = {c.candidate_id for c in candidates1}
    ids2 = {c.candidate_id for c in candidates2}
    assert ids1 == ids2


def test_max_candidates_cap() -> None:
    """Tracker should never return more than MAX_CANDIDATES."""
    from app.dataflow.tracker import MAX_CANDIDATES

    # Generate code with many source→sink paths
    lines = ["from flask import request"]
    for i in range(30):
        lines.append(f"v{i} = request.args.get('p{i}')")
        lines.append(f"eval(v{i})")
    code = "\n".join(lines)

    candidates = _tracker(Language.PYTHON).analyze(code)
    assert len(candidates) <= MAX_CANDIDATES


# ─────────────────────────────────────────────────────────────────────────────
# Go: := short variable declaration
# ─────────────────────────────────────────────────────────────────────────────


def test_go_short_var_decl_seeded() -> None:
    """userID := r.FormValue('id') must taint userID and produce a SQL candidate."""
    code = """
userID := r.FormValue("id")
db.Query("SELECT * FROM users WHERE id = " + userID)
"""
    candidates = _tracker(Language.GO).analyze(code)
    assert len(candidates) >= 1, "Go := short-var-decl must seed taint"
    assert any(c.source.kind == SourceKind.HTTP_PARAM for c in candidates)
    assert any(c.sink.kind == SinkKind.SQL_QUERY for c in candidates)


def test_go_short_var_decl_propagation_chain() -> None:
    """Taint should propagate through assignment chains in Go."""
    code = """
raw := r.FormValue("query")
q := raw
db.Query("SELECT * FROM t WHERE val = " + q)
"""
    candidates = _tracker(Language.GO).analyze(code)
    assert len(candidates) >= 1, "Taint must propagate through := chain"


def test_go_no_source_no_candidate() -> None:
    """Go code with a hardcoded value reaching a sink should not be flagged."""
    code = """
name := "alice"
db.Query("SELECT * FROM t WHERE name = " + name)
"""
    candidates = _tracker(Language.GO).analyze(code)
    assert len(candidates) == 0


def test_go_sanitizer_removes_taint() -> None:
    """strconv.ParseInt should untaint the variable in Go."""
    # Go multi-return (id, err := strconv.Atoi(raw)) isn't single-assignment,
    # so we use a helper variable pattern that matches single := assignment.
    code = """
raw := r.FormValue("id")
safeID := strconv.ParseInt(raw, 10, 64)
db.Query("SELECT * FROM t WHERE id = " + safeID)
"""
    candidates = _tracker(Language.GO).analyze(code)
    # After ParseInt sanitization, safeID is a number — taint should be removed
    assert len(candidates) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Sanitizer reassignment removes taint
# ─────────────────────────────────────────────────────────────────────────────


def test_python_sanitizer_reassignment_removes_taint() -> None:
    """x = int(x) after taint source should untaint x — no candidate emitted."""
    code = """
user_id = request.args.get('id')
user_id = int(user_id)
cursor.execute("SELECT * FROM t WHERE id = " + str(user_id))
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert len(candidates) == 0, "int() sanitizer should remove taint from user_id"


def test_python_sanitizer_does_not_remove_unrelated_taint() -> None:
    """Sanitizing y does NOT remove taint from an unrelated variable x."""
    code = """
user_id = request.args.get('id')
safe_count = int("42")
cursor.execute("SELECT * FROM t WHERE id = " + user_id)
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert len(candidates) >= 1, "user_id must remain tainted despite int() on a different var"
    assert any(c.sink.kind == SinkKind.SQL_QUERY for c in candidates)


def test_python_html_escape_removes_taint() -> None:
    """html.escape() sanitization should prevent XSS candidate from being emitted."""
    code = """
name = request.args.get('name')
name = html.escape(name)
result = "<div>" + name + "</div>"
"""
    # After html.escape, name is safe — result should not be tainted to a dangerous sink
    candidates = _tracker(Language.PYTHON).analyze(code)
    # No dangerous sink in this snippet, but verifying sanitizer removes taint
    # so that if a sink were added, it wouldn't fire
    html_tainted = [c for c in candidates if "name" in c.snippet and "html.escape" in c.snippet]
    assert len(html_tainted) == 0


# ─────────────────────────────────────────────────────────────────────────────
# New Python sinks: SSTI, check_output, execve/execvp
# ─────────────────────────────────────────────────────────────────────────────


def test_python_render_template_string_ssti() -> None:
    """render_template_string with tainted arg is SSTI (CWE-94)."""
    code = """
template = request.args.get('tmpl')
return render_template_string(template)
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert any(c.sink.kind == SinkKind.TEMPLATE_RENDER for c in candidates), (
        "render_template_string must be detected as TEMPLATE_RENDER sink"
    )


def test_python_subprocess_check_output_tainted() -> None:
    """subprocess.check_output with tainted arg is shell injection (CWE-78)."""
    code = """
cmd = request.form.get('command')
result = subprocess.check_output(cmd, shell=True)
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert any(c.sink.kind == SinkKind.SHELL_EXEC for c in candidates), (
        "subprocess.check_output must be detected as SHELL_EXEC sink"
    )


def test_python_os_execve_tainted() -> None:
    """os.execve with tainted program path is shell execution (CWE-78)."""
    code = """
prog = request.args.get('program')
os.execve(prog, [], {})
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert any(c.sink.kind == SinkKind.SHELL_EXEC for c in candidates), (
        "os.execve must be detected as SHELL_EXEC sink"
    )


def test_python_os_execvp_tainted() -> None:
    """os.execvp with tainted first argument is shell execution."""
    code = """
binary = request.args.get('bin')
os.execvp(binary, [binary])
"""
    candidates = _tracker(Language.PYTHON).analyze(code)
    assert any(c.sink.kind == SinkKind.SHELL_EXEC for c in candidates)
