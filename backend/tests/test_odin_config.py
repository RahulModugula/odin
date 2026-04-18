"""Tests for .odin.yml project config loader."""

import textwrap
from pathlib import Path

import pytest

from app.cli.config import OdinConfig, QualityGate, find_config, load_config

# ── QualityGate ───────────────────────────────────────────────────────────────


def test_quality_gate_inactive_by_default() -> None:
    gate = QualityGate()
    assert not gate.is_active()


def test_quality_gate_active_with_min_score() -> None:
    gate = QualityGate(min_score=70)
    assert gate.is_active()


def test_quality_gate_active_with_max_critical() -> None:
    gate = QualityGate(max_critical=0)
    assert gate.is_active()


def test_quality_gate_from_dict() -> None:
    gate = QualityGate.from_dict({"min_score": 80, "max_critical": 0, "max_high": 5})
    assert gate.min_score == 80
    assert gate.max_critical == 0
    assert gate.max_high == 5


# ── OdinConfig.is_ignored ─────────────────────────────────────────────────────


def test_is_ignored_matching_rule_and_path() -> None:
    from app.cli.config import IgnoreRule

    cfg = OdinConfig(ignore=[IgnoreRule(rule="eval() usage", path="scripts/")])
    assert cfg.is_ignored("eval() usage detected", "project/scripts/build.py")


def test_is_ignored_rule_no_match() -> None:
    from app.cli.config import IgnoreRule

    cfg = OdinConfig(ignore=[IgnoreRule(rule="eval() usage", path="scripts/")])
    assert not cfg.is_ignored("SQL injection", "project/scripts/build.py")


def test_is_ignored_path_no_match() -> None:
    from app.cli.config import IgnoreRule

    cfg = OdinConfig(ignore=[IgnoreRule(rule="eval() usage", path="scripts/")])
    assert not cfg.is_ignored("eval() usage detected", "src/app/main.py")


def test_is_ignored_no_path_matches_all_files() -> None:
    from app.cli.config import IgnoreRule

    cfg = OdinConfig(ignore=[IgnoreRule(rule="hardcoded secret")])
    assert cfg.is_ignored("Hardcoded secret detected", "anywhere/any.py")


def test_is_ignored_case_insensitive() -> None:
    from app.cli.config import IgnoreRule

    cfg = OdinConfig(ignore=[IgnoreRule(rule="HARDCODED SECRET")])
    assert cfg.is_ignored("Hardcoded secret detected", "any.py")


# ── OdinConfig.is_excluded ────────────────────────────────────────────────────


def test_is_excluded_glob_match() -> None:
    cfg = OdinConfig(exclude=["node_modules/", "*.min.js"])
    assert cfg.is_excluded("project/node_modules/lodash/index.js")
    assert cfg.is_excluded("dist/bundle.min.js")


def test_is_excluded_no_match() -> None:
    cfg = OdinConfig(exclude=["node_modules/"])
    assert not cfg.is_excluded("src/app/main.py")


# ── find_config ───────────────────────────────────────────────────────────────


def test_find_config_finds_file(tmp_path: Path) -> None:
    config_file = tmp_path / ".odin.yml"
    config_file.write_text("min_severity: high\n")
    found = find_config(tmp_path)
    assert found == config_file


def test_find_config_walks_up(tmp_path: Path) -> None:
    config_file = tmp_path / ".odin.yml"
    config_file.write_text("fail_on: critical\n")
    subdir = tmp_path / "src" / "app"
    subdir.mkdir(parents=True)
    found = find_config(subdir)
    assert found == config_file


def test_find_config_returns_none_when_absent(tmp_path: Path) -> None:
    found = find_config(tmp_path)
    assert found is None


def test_find_config_prefers_yml_over_yaml(tmp_path: Path) -> None:
    yml = tmp_path / ".odin.yml"
    yaml = tmp_path / ".odin.yaml"
    yml.write_text("min_severity: low\n")
    yaml.write_text("min_severity: high\n")
    found = find_config(tmp_path)
    assert found == yml


# ── load_config ───────────────────────────────────────────────────────────────


def test_load_config_returns_defaults_when_no_file(tmp_path: Path) -> None:
    cfg = load_config(tmp_path)
    assert cfg.min_severity == "low"
    assert cfg.fail_on == "high"
    assert cfg.min_confidence == 0.0
    assert cfg.config_path is None


def test_load_config_parses_basic_fields(tmp_path: Path) -> None:
    (tmp_path / ".odin.yml").write_text(
        textwrap.dedent("""\
        min_severity: high
        fail_on: critical
        min_confidence: 0.7
        """)
    )
    cfg = load_config(tmp_path)
    assert cfg.min_severity == "high"
    assert cfg.fail_on == "critical"
    assert cfg.min_confidence == pytest.approx(0.7)


def test_load_config_quality_gate(tmp_path: Path) -> None:
    pytest.importorskip("yaml", reason="PyYAML required for nested YAML parsing")
    (tmp_path / ".odin.yml").write_text(
        textwrap.dedent("""\
        quality_gate:
          min_score: 75
          max_critical: 0
          max_high: 3
        """)
    )
    cfg = load_config(tmp_path)
    assert cfg.quality_gate.min_score == 75
    assert cfg.quality_gate.max_critical == 0
    assert cfg.quality_gate.max_high == 3
    assert cfg.quality_gate.is_active()


def test_load_config_ignore_rules(tmp_path: Path) -> None:
    pytest.importorskip("yaml", reason="PyYAML required for list parsing")
    (tmp_path / ".odin.yml").write_text(
        textwrap.dedent("""\
        ignore:
          - rule: "eval() usage"
            path: "scripts/"
            reason: "build-time only"
        """)
    )
    cfg = load_config(tmp_path)
    assert len(cfg.ignore) == 1
    assert cfg.ignore[0].rule == "eval() usage"
    assert cfg.ignore[0].path == "scripts/"


def test_load_config_exclude_patterns(tmp_path: Path) -> None:
    pytest.importorskip("yaml", reason="PyYAML required for list parsing")
    (tmp_path / ".odin.yml").write_text(
        textwrap.dedent("""\
        exclude:
          - "node_modules/"
          - "migrations/"
        """)
    )
    cfg = load_config(tmp_path)
    assert "node_modules/" in cfg.exclude
    assert "migrations/" in cfg.exclude


def test_load_config_invalid_yaml_returns_defaults(tmp_path: Path) -> None:
    (tmp_path / ".odin.yml").write_text("{{{{invalid yaml}}}")
    cfg = load_config(tmp_path)
    # Should not raise; should return defaults
    assert cfg.min_severity == "low"


def test_load_config_config_path_populated(tmp_path: Path) -> None:
    (tmp_path / ".odin.yml").write_text("min_severity: high\n")
    cfg = load_config(tmp_path)
    assert cfg.config_path is not None
    assert cfg.config_path.name == ".odin.yml"


def test_load_config_max_findings(tmp_path: Path) -> None:
    (tmp_path / ".odin.yml").write_text("max_findings: 7\n")
    cfg = load_config(tmp_path)
    assert cfg.max_findings == 7


def test_load_config_max_findings_defaults_to_zero(tmp_path: Path) -> None:
    cfg = load_config(tmp_path)
    assert cfg.max_findings == 0
