"""Tests for the deterministic rules engine."""

from __future__ import annotations

import pytest

from app.models.enums import Language
from app.rules.engine import RuleEngine
from app.rules.registry import register_all


@pytest.fixture()
def engine() -> RuleEngine:
    """A freshly initialized rule engine for each test."""
    from app.rules.builtin import cross_language_rules, js_rules, python_rules
    from app.rules.engine import RuleEngine

    eng = RuleEngine()
    for rule in python_rules.ALL_RULES:
        eng.register(rule)
    for rule in js_rules.ALL_RULES:
        eng.register(rule)
    for rule in cross_language_rules.ALL_RULES:
        eng.register(rule)
    return eng


# ── Engine bookkeeping ────────────────────────────────────────────────────────


def test_register_all_idempotent() -> None:
    """Calling register_all twice should not double-register rules."""
    from app.rules.engine import rule_engine

    register_all()
    count_after_first = len(rule_engine._rules)
    register_all()
    assert len(rule_engine._rules) == count_after_first


def test_is_initialized_after_register_all() -> None:
    from app.rules.engine import rule_engine

    register_all()
    assert rule_engine.is_initialized()


def test_disabled_rules_skipped(engine: RuleEngine) -> None:
    code = "try:\n    pass\nexcept:\n    pass\n"
    findings = engine.check_all(code, Language.PYTHON, disabled_rules=["PY001"])
    titles = [f.title for f in findings]
    assert not any("bare except" in t.lower() for t in titles)


def test_source_stamped_on_all_findings(engine: RuleEngine) -> None:
    code = "try:\n    pass\nexcept:\n    pass\n"
    findings = engine.check_all(code, Language.PYTHON)
    assert all(f.source == "rule" for f in findings)


# ── Deduplication ─────────────────────────────────────────────────────────────


def test_deduplication_removes_duplicate_credential_findings(engine: RuleEngine) -> None:
    """PY004 and CL004 both match a hardcoded password — only one should survive."""
    code = "password = 'super_secret_123'\n"
    findings = engine.check_all(code, Language.PYTHON)
    # All findings should be for line 1, category security
    security_line1 = [f for f in findings if f.line_start == 1 and f.category.value == "security"]
    assert len(security_line1) == 1, f"Expected 1 after dedup, got {len(security_line1)}"


# ── Python rules ─────────────────────────────────────────────────────────────


def test_py001_bare_except(engine: RuleEngine) -> None:
    code = "try:\n    x = 1\nexcept:\n    pass\n"
    findings = engine.check_all(code, Language.PYTHON)
    assert any("bare except" in f.title.lower() for f in findings)


def test_py001_specific_except_is_clean(engine: RuleEngine) -> None:
    code = "try:\n    x = 1\nexcept ValueError:\n    pass\n"
    findings = engine.check_all(code, Language.PYTHON)
    assert not any("bare except" in f.title.lower() for f in findings)


def test_py002_mutable_default_arg(engine: RuleEngine) -> None:
    code = "def foo(items=[]):\n    return items\n"
    findings = engine.check_all(code, Language.PYTHON)
    assert any("mutable default" in f.title.lower() for f in findings)


def test_py003_eval_usage(engine: RuleEngine) -> None:
    code = "result = eval(user_input)\n"
    findings = engine.check_all(code, Language.PYTHON)
    assert any("eval" in f.title.lower() for f in findings)


def test_py004_hardcoded_secret(engine: RuleEngine) -> None:
    code = "api_key = 'sk-abc123def456'\n"
    findings = engine.check_all(code, Language.PYTHON)
    assert any(f.severity.value == "critical" and f.line_start == 1 for f in findings)


def test_py004_env_var_not_flagged(engine: RuleEngine) -> None:
    code = "api_key = os.environ['API_KEY']\n"
    findings = engine.check_all(code, Language.PYTHON)
    assert not any("hardcoded" in f.title.lower() for f in findings)


def test_py005_sql_injection(engine: RuleEngine) -> None:
    code = 'query = f"SELECT * FROM users WHERE id = {user_id}"\n'
    findings = engine.check_all(code, Language.PYTHON)
    assert any("sql" in f.title.lower() for f in findings)


# ── JavaScript rules ──────────────────────────────────────────────────────────


def test_js001_var_usage(engine: RuleEngine) -> None:
    code = "var x = 1;\n"
    findings = engine.check_all(code, Language.JAVASCRIPT)
    assert any("var" in f.title.lower() for f in findings)


def test_js002_console_log(engine: RuleEngine) -> None:
    code = "console.log('debug');\n"
    findings = engine.check_all(code, Language.JAVASCRIPT)
    assert any("console.log" in f.title.lower() for f in findings)


def test_js003_xss_inner_html(engine: RuleEngine) -> None:
    code = "element.innerHTML = userInput;\n"
    findings = engine.check_all(code, Language.JAVASCRIPT)
    assert any("xss" in f.title.lower() or "html" in f.title.lower() for f in findings)


def test_ts001_any_type(engine: RuleEngine) -> None:
    code = "let data: any = fetchData();\n"
    findings = engine.check_all(code, Language.TYPESCRIPT)
    assert any("any" in f.title.lower() for f in findings)


# ── Cross-language rules ──────────────────────────────────────────────────────


def test_cl001_todo_comment(engine: RuleEngine) -> None:
    code = "# TODO: fix this later\nx = 1\n"
    findings = engine.check_all(code, Language.PYTHON)
    assert any("todo" in f.title.lower() or "fixme" in f.title.lower() for f in findings)


def test_cl004_hardcoded_credential_all_languages(engine: RuleEngine) -> None:
    """CL004 fires for non-Python languages (JS, TS, Go) where PY004 doesn't apply."""
    code = "const password = 'secret_123';\n"
    findings = engine.check_all(code, Language.JAVASCRIPT)
    assert any(f.severity.value == "critical" and f.line_start == 1 for f in findings)


def test_language_filter_no_python_rules_on_go(engine: RuleEngine) -> None:
    """Python-specific rules should not fire on Go code."""
    code = "try:\n    x = 1\nexcept:\n    pass\n"  # syntactically Python, but language=go
    findings = engine.check_all(code, Language.GO)
    assert not any(f.rule_id if hasattr(f, "rule_id") else "" == "PY001" for f in findings)
    # bare except is Python-only; no findings should mention it for Go
    assert not any("bare except" in f.title.lower() for f in findings)


# ── Quality gate ─────────────────────────────────────────────────────────────


def _make_review_result(score: int, findings=None):  # type: ignore[no-untyped-def]
    from app.models.enums import Language
    from app.models.schemas import CodeMetrics, ReviewResult

    return ReviewResult(
        metrics=CodeMetrics(
            lines_of_code=10,
            num_functions=1,
            num_classes=0,
            avg_function_length=5.0,
            max_function_length=10,
            max_nesting_depth=2,
            cyclomatic_complexity=2,
            comment_ratio=0.1,
            import_count=1,
        ),
        findings=findings or [],
        overall_score=score,
        language=Language.PYTHON,
    )


def test_quality_gate_passes_clean_code() -> None:
    from app.services.quality_gate import QualityGateConfig, evaluate

    config = QualityGateConfig(min_score=70, max_critical=0)
    result = evaluate([_make_review_result(95)], config=config)
    assert result.passed
    assert result.score == 95


def test_quality_gate_fails_on_critical() -> None:
    from app.models.enums import Category, Severity
    from app.models.schemas import Finding
    from app.services.quality_gate import QualityGateConfig, evaluate

    critical = Finding(
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        title="SQL injection",
        description="Bad query",
    )
    config = QualityGateConfig(min_score=0, max_critical=0)
    result = evaluate([_make_review_result(50, findings=[critical])], config=config)
    assert not result.passed


def test_quality_gate_fails_on_low_score() -> None:
    from app.services.quality_gate import QualityGateConfig, evaluate

    config = QualityGateConfig(min_score=70, max_critical=5)
    result = evaluate([_make_review_result(40)], config=config)
    assert not result.passed


# ── PY010 UnsafeDeserialization ───────────────────────────────────────────────


def test_unsafe_deserialization_pickle(engine: RuleEngine) -> None:
    code = "import pickle\ndata = pickle.loads(user_bytes)\n"
    findings = engine.check_all(code, Language.PYTHON)
    assert any("pickle" in f.title.lower() or "deserializ" in f.title.lower() for f in findings)


def test_unsafe_deserialization_yaml(engine: RuleEngine) -> None:
    code = "import yaml\ndata = yaml.load(stream)\n"
    findings = engine.check_all(code, Language.PYTHON)
    assert any("yaml" in f.description.lower() or "deserializ" in f.title.lower() for f in findings)


# ── PY011 CommandInjection ───────────────────────────────────────────────────


def test_command_injection_subprocess(engine: RuleEngine) -> None:
    code = 'import subprocess\nsubprocess.run(f"ls {user_input}", shell=True)\n'
    findings = engine.check_all(code, Language.PYTHON)
    assert any("command" in f.title.lower() or "injection" in f.title.lower() for f in findings)


def test_command_injection_os_system(engine: RuleEngine) -> None:
    code = 'import os\nos.system(f"echo {user_input}")\n'
    findings = engine.check_all(code, Language.PYTHON)
    assert any("command" in f.title.lower() or "injection" in f.title.lower() for f in findings)


# ── PY012 InsecureRandom ──────────────────────────────────────────────────────


def test_insecure_random_in_security_context(engine: RuleEngine) -> None:
    code = "import random\ntoken = random.randint(0, 999999)\n"
    findings = engine.check_all(code, Language.PYTHON)
    assert any("prng" in f.title.lower() or "weak" in f.title.lower() for f in findings)


def test_insecure_random_no_flag_outside_security(engine: RuleEngine) -> None:
    code = "import random\nx = random.randint(0, 10)\n"
    findings = engine.check_all(code, Language.PYTHON)
    assert not any("random" in f.title.lower() for f in findings)


# ── PY014 SSRF ───────────────────────────────────────────────────────────────


def test_ssrf_rule_fires_on_user_input(engine: RuleEngine) -> None:
    code = (
        "from flask import request\n"
        "import requests\n"
        "url = request.args.get('url')\n"
        "resp = requests.get(url)\n"
    )
    findings = engine.check_all(code, Language.PYTHON)
    assert any("ssrf" in f.title.lower() or "request forgery" in f.title.lower() for f in findings)


# ── JS005 JWTMisuse ───────────────────────────────────────────────────────────


def test_jwt_decode_without_verify(engine: RuleEngine) -> None:
    code = "const payload = jwt.decode(token);\nconst userId = payload.userId;\n"
    findings = engine.check_all(code, Language.JAVASCRIPT)
    assert any("jwt" in f.title.lower() for f in findings)


def test_jwt_verify_present_suppresses_decode_finding(engine: RuleEngine) -> None:
    code = "jwt.verify(token, secret, (err, decoded) => {});\nconst payload = jwt.decode(token);\n"
    findings = engine.check_all(code, Language.JAVASCRIPT)
    decode_findings = [f for f in findings if "skips signature" in f.title]
    assert len(decode_findings) == 0


# ── JS006 PrototypePollution ──────────────────────────────────────────────────


def test_prototype_pollution_unguarded_merge(engine: RuleEngine) -> None:
    code = (
        "function deepMerge(target, source) {\n"
        "  for (const key of Object.keys(source)) {\n"
        "    target[key] = source[key];\n"
        "  }\n"
        "}\n"
    )
    findings = engine.check_all(code, Language.JAVASCRIPT)
    assert any("prototype" in f.title.lower() or "pollution" in f.title.lower() for f in findings)


def test_prototype_pollution_guarded_merge_no_finding(engine: RuleEngine) -> None:
    code = (
        "function deepMerge(target, source) {\n"
        "  for (const key of Object.keys(source)) {\n"
        "    if (key === '__proto__') continue;\n"
        "    target[key] = source[key];\n"
        "  }\n"
        "}\n"
    )
    findings = engine.check_all(code, Language.JAVASCRIPT)
    assert not any("pollution" in f.title.lower() for f in findings)
