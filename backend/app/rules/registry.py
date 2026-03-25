"""Auto-register all built-in rules with the global rule engine."""

from __future__ import annotations

from app.rules.builtin import cross_language_rules, js_rules, python_rules
from app.rules.engine import rule_engine


def register_all() -> None:
    """Register every built-in rule.  Safe to call more than once."""
    for rule in python_rules.ALL_RULES:
        rule_engine.register(rule)
    for rule in js_rules.ALL_RULES:
        rule_engine.register(rule)
    for rule in cross_language_rules.ALL_RULES:
        rule_engine.register(rule)
