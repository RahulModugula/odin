"""Policy-as-code: load team-written YAML rules from ``.odin/rules/``.

This is the "bring-your-own-rule" extension point. Teams drop YAML files into
``.odin/rules/`` and each file becomes a ``Rule`` that participates in the
standard rule engine — so they benefit from dedup, severity filtering, SARIF
output, and (optionally) LLM-backed explanations.

Schema
------

``` yaml
id: TEAM001                          # unique (prefix TEAM/CUSTOM distinguishes from built-ins)
name: No direct DB access outside repository layer
description: |-                      # optional; used in finding body
  Functions must not hit the DB unless they live in a repositories/ package.
severity: high                       # critical | high | medium | low | info
# one of: security | quality | docs | performance | maintainability | testing
category: quality
languages: [python]

# Match layer — at least one of these must match for the rule to fire.
# Patterns are plain substrings on each line (fast, predictable, no regex trap).
match:
  any_of:
    - "db.execute("
    - "session.query("

# Optional scope: only fire if the file path matches one of these patterns
# OR does NOT match any excluded pattern.
exclude_paths: ["repositories/", "db/session.py"]

# Message shown to the developer
message: "{function_or_line} calls the database directly. Route through the repository layer."

# Optional LLM follow-up. If set AND the caller passes an llm, we ask the model
# to produce a tailored explanation per finding. Falls back to `message` if the
# LLM is unavailable (graceful offline mode).
llm_prompt: |
  Explain in one paragraph why '{snippet}' at line {line} in {file_path}
  breaks the 'no direct DB access' rule, and suggest the correct repository
  method to use. Be concrete.
```

The loader does not invoke the LLM — that would happen inside the agents.
It only parses, validates, and registers the rule so that the deterministic
match layer runs on every review.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.models.enums import Category, Language, Severity
from app.models.schemas import Finding
from app.rules.engine import Rule, RuleEngine

logger = logging.getLogger(__name__)


CUSTOM_RULES_DIR = Path(".odin/rules")
MAX_CUSTOM_RULES = 100  # sanity cap to keep rule engine latency bounded


@dataclass
class CustomRuleSpec:
    """Parsed YAML spec — validated inputs only, no runtime behavior."""

    id: str
    name: str
    severity: Severity
    category: Category
    languages: list[Language]
    any_of: list[str]
    description: str = ""
    message: str = ""
    exclude_paths: list[str] = field(default_factory=list)
    llm_prompt: str | None = None
    source_path: Path | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: Path) -> CustomRuleSpec:
        rule_id = str(data.get("id") or "").strip()
        if not rule_id:
            raise ValueError(f"{source_path}: missing required field 'id'")

        match_spec = data.get("match") or {}
        any_of = [str(p) for p in match_spec.get("any_of", []) if isinstance(p, str)]
        if not any_of:
            raise ValueError(f"{source_path}: at least one pattern required in match.any_of")

        severity = _coerce_severity(data.get("severity", "medium"), source_path)
        category = _coerce_category(data.get("category", "quality"), source_path)
        languages = _coerce_languages(data.get("languages", []), source_path)

        return cls(
            id=rule_id,
            name=str(data.get("name") or rule_id),
            description=str(data.get("description") or ""),
            severity=severity,
            category=category,
            languages=languages,
            any_of=any_of,
            message=str(data.get("message") or data.get("description") or ""),
            exclude_paths=[str(p) for p in data.get("exclude_paths") or [] if isinstance(p, str)],
            llm_prompt=data.get("llm_prompt"),
            source_path=source_path,
        )


def _coerce_severity(value: Any, source_path: Path) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError as exc:
        raise ValueError(
            f"{source_path}: invalid severity '{value}'. "
            "Must be one of: critical, high, medium, low, info"
        ) from exc


def _coerce_category(value: Any, source_path: Path) -> Category:
    try:
        return Category(str(value).lower())
    except ValueError as exc:
        raise ValueError(
            f"{source_path}: invalid category '{value}'. "
            f"Must be one of: {', '.join(c.value for c in Category)}"
        ) from exc


def _coerce_languages(value: Any, source_path: Path) -> list[Language]:
    if not value:
        raise ValueError(f"{source_path}: languages must list at least one language")
    if isinstance(value, str):
        value = [value]
    langs: list[Language] = []
    for item in value:
        try:
            langs.append(Language(str(item).lower()))
        except ValueError as exc:
            raise ValueError(
                f"{source_path}: unknown language '{item}'. "
                f"Supported: {', '.join(lang.value for lang in Language)}"
            ) from exc
    return langs


# ── Runtime Rule: bridges a CustomRuleSpec into the existing RuleEngine ──────


class _CustomPatternRule(Rule):
    """A ``Rule`` backed by a user-authored YAML spec."""

    def __init__(self, spec: CustomRuleSpec) -> None:
        self.spec = spec
        self.id = spec.id
        self.name = spec.name
        self.description = spec.description
        self.severity = spec.severity
        self.category = spec.category
        self.languages = spec.languages

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        file_path = ""
        # structure carries file_path when set by the rule engine — best effort
        if structure is not None and hasattr(structure, "file_path"):
            file_path = getattr(structure, "file_path", "") or ""

        if file_path and self._is_excluded(file_path):
            return findings

        for line_no, line in enumerate(code.splitlines(), start=1):
            for pattern in self.spec.any_of:
                if pattern in line:
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            title=self.name,
                            description=self._format_message(line_no, line),
                            line_start=line_no,
                            line_end=line_no,
                            confidence=0.85,
                            source="rule",
                        )
                    )
                    break  # one finding per line per rule
        return findings

    def _is_excluded(self, file_path: str) -> bool:
        return any(
            fnmatch.fnmatch(file_path, f"*{pattern}*") for pattern in self.spec.exclude_paths
        )

    def _format_message(self, line_no: int, line: str) -> str:
        snippet = line.strip()[:120]
        message = self.spec.message or self.spec.description or self.spec.name
        # Only the {line}/{snippet}/{file_path} placeholders are filled in here —
        # other placeholders the user invented are left intact so the LLM prompt
        # layer can substitute them later.
        try:
            return message.format(line=line_no, snippet=snippet, file_path="")
        except (KeyError, IndexError):
            return f"{message}\n\nLine {line_no}: `{snippet}`"


# ── Discovery + loading ──────────────────────────────────────────────────────


def discover_rule_files(root: Path) -> list[Path]:
    """Return every ``*.yml`` / ``*.yaml`` file under ``root/.odin/rules/``."""
    rules_dir = root / CUSTOM_RULES_DIR
    if not rules_dir.is_dir():
        return []
    return sorted(
        p for p in rules_dir.rglob("*") if p.is_file() and p.suffix.lower() in (".yml", ".yaml")
    )


def load_custom_rules(root: Path) -> list[CustomRuleSpec]:
    """Parse every rule file under ``root/.odin/rules/``. Skips malformed files."""
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("PyYAML not installed; custom rules are disabled")
        return []

    specs: list[CustomRuleSpec] = []
    seen_ids: set[str] = set()

    for path in discover_rule_files(root):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("could not parse custom rule %s: %s", path, exc)
            continue
        if not isinstance(data, dict):
            logger.warning("custom rule %s must be a YAML mapping", path)
            continue
        try:
            spec = CustomRuleSpec.from_dict(data, path)
        except ValueError as exc:
            logger.warning("invalid custom rule: %s", exc)
            continue
        if spec.id in seen_ids:
            logger.warning("duplicate custom rule id '%s' in %s — skipping", spec.id, path)
            continue
        seen_ids.add(spec.id)
        specs.append(spec)
        if len(specs) >= MAX_CUSTOM_RULES:
            logger.warning("custom rule cap (%d) reached; skipping the rest", MAX_CUSTOM_RULES)
            break

    return specs


def register_custom_rules(engine: RuleEngine, root: Path | None = None) -> int:
    """Load + register every ``.odin/rules/*.yml`` file found under ``root``.

    Returns the number of rules registered. Callers should invoke this during the
    usual ``register_all()`` bootstrap; the RuleEngine registrations are additive.
    """
    specs = load_custom_rules(root or Path.cwd())
    for spec in specs:
        engine.register(_CustomPatternRule(spec))
    if specs:
        logger.info("registered %d custom rule(s) from %s", len(specs), CUSTOM_RULES_DIR)
    return len(specs)
