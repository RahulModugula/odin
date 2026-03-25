"""Deterministic rule-based analysis engine (SonarQube-style)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.models.enums import Category, Language, Severity
from app.models.schemas import Finding


class Rule(ABC):
    """Base class for all deterministic rules.

    Subclasses must set class-level attributes and implement ``check()``.
    """

    id: str  # e.g. "PY001"
    name: str
    description: str = ""
    severity: Severity
    category: Category
    languages: list[Language]

    @abstractmethod
    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        """Run the rule against *code* and return any findings."""
        ...


class RuleEngine:
    """Collects rules and runs them against a piece of code."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._initialized: bool = False

    def register(self, rule: Rule) -> None:
        """Register a rule instance with the engine."""
        self._rules.append(rule)

    def is_initialized(self) -> bool:
        """Return True if rules have been registered via register_all()."""
        return self._initialized

    def mark_initialized(self) -> None:
        """Mark the engine as initialized (called by register_all)."""
        self._initialized = True

    def check_all(
        self,
        code: str,
        language: Language,
        disabled_rules: list[str] | None = None,
    ) -> list[Finding]:
        """Run all applicable, non-disabled rules and return their findings.

        Deduplicates findings by (line_start, category, title prefix) so that
        overlapping rules (e.g. PY004 and CL004 both detecting hardcoded secrets)
        only surface the higher-confidence result once.
        """
        disabled = set(disabled_rules or [])
        raw_findings: list[Finding] = []

        # Parse the tree once and share it across all rules
        from app.parsers.tree_sitter_parser import parse_code

        try:
            structure = parse_code(code, language)
        except Exception:
            structure = None

        for rule in self._rules:
            if rule.id in disabled:
                continue
            if language not in rule.languages:
                continue
            try:
                rule_findings = rule.check(code, language, structure=structure)
                for f in rule_findings:
                    # Stamp source so consumers can distinguish rule vs AI findings
                    if f.source is None:
                        f.source = "rule"
                raw_findings.extend(rule_findings)
            except Exception:
                pass

        # Deduplicate: same (line, category) keeps highest confidence finding.
        # This handles overlapping rules like PY004 + CL004 both flagging the same
        # hardcoded-secret line — we surface the more confident result once.
        seen: dict[tuple[int | None, str], Finding] = {}
        for f in raw_findings:
            key = (f.line_start, f.category.value)
            existing = seen.get(key)
            if existing is None or f.confidence > existing.confidence:
                seen[key] = f

        return list(seen.values())


# Module-level singleton — imported by agents and the API
rule_engine = RuleEngine()
