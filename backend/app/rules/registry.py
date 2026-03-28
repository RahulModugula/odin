"""Auto-register all built-in rules with the global rule engine."""

from __future__ import annotations

from app.rules.builtin import (
    cross_language_rules,
    go_rules,
    java_rules,
    js_rules,
    performance_rules,
    python_rules,
    rust_rules,
)
from app.rules.engine import rule_engine


def register_all() -> None:
    """Register every built-in rule.  Idempotent — safe to call more than once."""
    if rule_engine.is_initialized():
        return
    for rule in python_rules.ALL_RULES:
        rule_engine.register(rule)
    for rule in js_rules.ALL_RULES:
        rule_engine.register(rule)
    for rule in go_rules.ALL_RULES:
        rule_engine.register(rule)
    for rule in java_rules.ALL_RULES:
        rule_engine.register(rule)
    for rule in rust_rules.ALL_RULES:
        rule_engine.register(rule)
    for rule in performance_rules.ALL_RULES:
        rule_engine.register(rule)
    for rule in cross_language_rules.ALL_RULES:
        rule_engine.register(rule)
    rule_engine.mark_initialized()
