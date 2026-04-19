"""Tests for .odin/rules/*.yml policy-as-code custom rule loader."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

pytest.importorskip("yaml", reason="PyYAML required for custom rule tests")

from app.models.enums import Category, Language, Severity
from app.rules.custom_loader import (
    CUSTOM_RULES_DIR,
    CustomRuleSpec,
    _CustomPatternRule,
    discover_rule_files,
    load_custom_rules,
    register_custom_rules,
)
from app.rules.engine import RuleEngine

# ── Parsing & validation ─────────────────────────────────────────────────────


def _write_rule(tmp_path: Path, filename: str, body: str) -> Path:
    rules_dir = tmp_path / CUSTOM_RULES_DIR
    rules_dir.mkdir(parents=True, exist_ok=True)
    path = rules_dir / filename
    path.write_text(textwrap.dedent(body))
    return path


def test_loads_valid_rule(tmp_path: Path) -> None:
    _write_rule(
        tmp_path,
        "no-direct-db.yml",
        """\
        id: TEAM001
        name: No direct DB access
        severity: high
        category: quality
        languages: [python]
        match:
          any_of:
            - "db.execute("
            - "session.query("
        message: "Route through repositories/"
        """,
    )
    specs = load_custom_rules(tmp_path)
    assert len(specs) == 1
    spec = specs[0]
    assert spec.id == "TEAM001"
    assert spec.severity is Severity.HIGH
    assert spec.category is Category.QUALITY
    assert Language.PYTHON in spec.languages
    assert "db.execute(" in spec.any_of


def test_skips_missing_id(tmp_path: Path) -> None:
    _write_rule(
        tmp_path,
        "bad.yml",
        """\
        name: missing id
        severity: high
        category: quality
        languages: [python]
        match:
          any_of: ["x"]
        """,
    )
    assert load_custom_rules(tmp_path) == []


def test_skips_rule_without_match_patterns(tmp_path: Path) -> None:
    _write_rule(
        tmp_path,
        "no-match.yml",
        """\
        id: TEAM002
        name: no patterns
        severity: high
        category: quality
        languages: [python]
        match:
          any_of: []
        """,
    )
    assert load_custom_rules(tmp_path) == []


def test_skips_invalid_severity(tmp_path: Path) -> None:
    _write_rule(
        tmp_path,
        "bad-sev.yml",
        """\
        id: TEAM003
        severity: SUPER_BAD
        category: quality
        languages: [python]
        match:
          any_of: ["x"]
        """,
    )
    assert load_custom_rules(tmp_path) == []


def test_skips_unknown_language(tmp_path: Path) -> None:
    _write_rule(
        tmp_path,
        "unknown-lang.yml",
        """\
        id: TEAM004
        severity: high
        category: quality
        languages: [cobol]
        match:
          any_of: ["x"]
        """,
    )
    assert load_custom_rules(tmp_path) == []


def test_duplicate_ids_are_skipped(tmp_path: Path) -> None:
    body = """\
    id: TEAM005
    severity: high
    category: quality
    languages: [python]
    match:
      any_of: ["x"]
    """
    _write_rule(tmp_path, "a.yml", body)
    _write_rule(tmp_path, "b.yml", body)
    specs = load_custom_rules(tmp_path)
    assert len(specs) == 1


def test_discovers_only_yaml_files(tmp_path: Path) -> None:
    _write_rule(
        tmp_path,
        "ok.yml",
        "id: T1\nseverity: high\ncategory: quality\nlanguages: [python]\nmatch:\n  any_of: ['x']\n",
    )
    (tmp_path / CUSTOM_RULES_DIR / "README.md").write_text("# docs")
    (tmp_path / CUSTOM_RULES_DIR / "notes.txt").write_text("not a rule")
    files = discover_rule_files(tmp_path)
    assert len(files) == 1
    assert files[0].suffix == ".yml"


def test_no_rules_dir_returns_empty(tmp_path: Path) -> None:
    # No .odin/rules/ anywhere
    assert load_custom_rules(tmp_path) == []


# ── Matching behavior ────────────────────────────────────────────────────────


def _spec(**kwargs: object) -> CustomRuleSpec:
    defaults: dict = {
        "id": "T1",
        "name": "No DB direct",
        "severity": Severity.HIGH,
        "category": Category.QUALITY,
        "languages": [Language.PYTHON],
        "any_of": ["db.execute("],
        "message": "Route through repositories",
    }
    defaults.update(kwargs)  # type: ignore[arg-type]
    return CustomRuleSpec(**defaults)  # type: ignore[arg-type]


def test_rule_fires_on_matching_line() -> None:
    rule = _CustomPatternRule(_spec())
    code = "def foo():\n    db.execute('select 1')\n"
    findings = rule.check(code, Language.PYTHON)
    assert len(findings) == 1
    assert findings[0].line_start == 2
    assert findings[0].severity is Severity.HIGH
    assert findings[0].source == "rule"


def test_rule_skips_non_matching_code() -> None:
    rule = _CustomPatternRule(_spec())
    code = "x = 1\ny = 2\n"
    assert rule.check(code, Language.PYTHON) == []


def test_rule_emits_one_finding_per_matching_line() -> None:
    rule = _CustomPatternRule(_spec(any_of=["db.execute(", "session.query("]))
    code = "db.execute('a')\nsession.query(User)\nok = True\n"
    findings = rule.check(code, Language.PYTHON)
    assert len(findings) == 2
    assert [f.line_start for f in findings] == [1, 2]


def test_rule_respects_wrong_language() -> None:
    rule = _CustomPatternRule(_spec(languages=[Language.PYTHON]))
    # check() itself doesn't gate on language — the engine does; but verify
    # that the registry logic (below) only dispatches for matching languages.
    engine = RuleEngine()
    engine.register(rule)
    code = "db.execute('x')\n"
    py_findings = engine.check_all(code, Language.PYTHON)
    go_findings = engine.check_all(code, Language.GO)
    assert len(py_findings) == 1
    assert go_findings == []


# ── register_custom_rules + engine integration ───────────────────────────────


def test_register_loads_and_counts(tmp_path: Path) -> None:
    _write_rule(
        tmp_path,
        "r.yml",
        """\
        id: TEAM010
        severity: medium
        category: quality
        languages: [python]
        match:
          any_of: ["eval("]
        """,
    )
    engine = RuleEngine()
    count = register_custom_rules(engine, tmp_path)
    assert count == 1
    findings = engine.check_all("x = eval('1+1')\n", Language.PYTHON)
    assert len(findings) == 1
    assert findings[0].title == "TEAM010" or "eval" in findings[0].description


# ── End-to-end: committed example rule ────────────────────────────────────────


_REPO_ROOT = Path(__file__).resolve().parent.parent.parent  # odin workspace root


def test_committed_example_rule_detects_pickle_loads() -> None:
    """End-to-end: load the committed example rule and verify it catches pickle.loads."""
    specs = load_custom_rules(_REPO_ROOT)
    # Find the pickle rule by id or name
    pickle_rules = [s for s in specs if "pickle" in s.id.lower() or "pickle" in s.name.lower()]
    assert len(pickle_rules) >= 1, (
        f"Expected at least one pickle rule, found: {[s.id for s in specs]}"
    )

    engine = RuleEngine()
    for spec in pickle_rules:
        engine.register(_CustomPatternRule(spec))

    code = "import pickle\ndata = pickle.loads(user_input)\n"
    findings = engine.check_all(code, Language.PYTHON)
    assert len(findings) >= 1
    # Verify finding attributes
    f = findings[0]
    assert f.severity is not None
    assert f.line_start is not None


def test_committed_example_rule_no_false_positive() -> None:
    """Negative control: the committed rule should not fire on safe code."""
    specs = load_custom_rules(_REPO_ROOT)
    pickle_rules = [s for s in specs if "pickle" in s.id.lower() or "pickle" in s.name.lower()]
    if not pickle_rules:
        pytest.skip("No pickle rule found")

    engine = RuleEngine()
    for spec in pickle_rules:
        engine.register(_CustomPatternRule(spec))

    safe_code = "import json\ndata = json.loads(user_input)\n"
    findings = engine.check_all(safe_code, Language.PYTHON)
    assert len(findings) == 0
