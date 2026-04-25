"""Invariant: every built-in rule has a unique ID.

A duplicate ID silently shadows a rule at registration and makes findings'
`rule_id` ambiguous. This guards against the JS005 collision regressing.
"""

from __future__ import annotations

from collections import Counter

from app.rules.builtin import (
    cross_language_rules,
    go_rules,
    java_rules,
    js_rules,
    performance_rules,
    python_rules,
    rust_rules,
)

_MODULES = [
    python_rules,
    js_rules,
    go_rules,
    java_rules,
    rust_rules,
    performance_rules,
    cross_language_rules,
]


def test_builtin_rule_ids_are_unique():
    ids = [rule.id for mod in _MODULES for rule in mod.ALL_RULES]
    dupes = [rule_id for rule_id, n in Counter(ids).items() if n > 1]
    assert not dupes, f"duplicate rule IDs: {dupes}"


def test_builtin_rule_count_is_stable():
    # If this changes, update the README rules count/table intentionally.
    ids = [rule.id for mod in _MODULES for rule in mod.ALL_RULES]
    assert len(ids) == 51
