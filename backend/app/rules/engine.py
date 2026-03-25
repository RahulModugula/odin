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

    def register(self, rule: Rule) -> None:
        """Register a rule instance with the engine."""
        self._rules.append(rule)

    def check_all(
        self,
        code: str,
        language: Language,
        disabled_rules: list[str] | None = None,
    ) -> list[Finding]:
        """Run all applicable, non-disabled rules and return their findings."""
        disabled = set(disabled_rules or [])
        findings: list[Finding] = []

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
                findings.extend(rule_findings)
            except Exception:
                pass

        return findings


# Module-level singleton — imported by agents and the API
rule_engine = RuleEngine()
