"""Rust-specific deterministic rules."""

from __future__ import annotations

import re

from app.models.enums import Category, Language, Severity
from app.models.schemas import Finding
from app.rules.engine import Rule


class RustUnwrapRule(Rule):
    """RS001 — .unwrap() panics on None/Err and should be replaced with proper error handling."""

    id = "RS001"
    name = "unwrap() usage — potential panic"
    severity = Severity.MEDIUM
    category = Category.QUALITY
    languages = [Language.RUST]

    _pattern = re.compile(r"\.(unwrap)\s*\(\s*\)")
    # Test code is allowed to unwrap
    _TEST_ATTR = re.compile(r"#\[(?:test|cfg\(test\))")

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        in_test = False
        for i, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            if self._TEST_ATTR.search(stripped):
                in_test = True
            if in_test and stripped == "}":
                in_test = False
            if in_test or stripped.startswith("//"):
                continue
            if self._pattern.search(line):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="`.unwrap()` may panic on `None` or `Err`",
                        description=(
                            f"Line {i}: `.unwrap()` will panic if the value is `None` or `Err`. "
                            "In production code, panics crash the thread and cannot be caught "
                            "like exceptions."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Use the `?` operator to propagate errors, `.unwrap_or(default)`, "
                            "`.unwrap_or_else(|| ...)`, or `.expect(\"descriptive message\")`."
                        ),
                        confidence=0.85,
                    )
                )
        return findings


class RustUnsafeBlockRule(Rule):
    """RS002 — unsafe blocks bypass Rust's memory safety guarantees."""

    id = "RS002"
    name = "unsafe block usage"
    severity = Severity.HIGH
    category = Category.SECURITY
    languages = [Language.RUST]

    _pattern = re.compile(r"\bunsafe\s*\{")

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if self._pattern.search(line):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="`unsafe` block — memory safety not guaranteed",
                        description=(
                            f"Line {i}: `unsafe` blocks opt out of Rust's borrow checker and "
                            "memory safety guarantees. Bugs here can cause undefined behaviour, "
                            "buffer overflows, or use-after-free. CWE-119."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Minimize unsafe surface area. Document exactly why the unsafe is "
                            "sound, wrap it in a safe abstraction, and add tests or Miri checks."
                        ),
                        confidence=0.92,
                    )
                )
        return findings


class RustTodoMacroRule(Rule):
    """RS003 — todo!() / unimplemented!() panics at runtime."""

    id = "RS003"
    name = "todo!() or unimplemented!() macro in production code"
    severity = Severity.HIGH
    category = Category.QUALITY
    languages = [Language.RUST]

    _pattern = re.compile(r"\b(todo|unimplemented|unreachable)\s*!\s*\(")

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            m = self._pattern.search(line)
            if m:
                macro_name = m.group(1)
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title=f"`{macro_name}!()` macro panics at runtime",
                        description=(
                            f"Line {i}: `{macro_name}!()` is a placeholder that panics when "
                            "executed. If this code path is reached in production, the thread "
                            "will crash."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            f"Replace `{macro_name}!()` with a real implementation or return "
                            "a `Result::Err` / `Option::None` to signal the unimplemented case."
                        ),
                        confidence=0.9,
                    )
                )
        return findings


class RustCloneOveruseRule(Rule):
    """RS004 — Excessive .clone() calls may indicate ownership design issues."""

    id = "RS004"
    name = "Excessive .clone() usage"
    severity = Severity.LOW
    category = Category.PERFORMANCE
    languages = [Language.RUST]

    _pattern = re.compile(r"\.clone\s*\(\s*\)")

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        clone_lines: list[int] = []

        for i, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if self._pattern.search(line):
                clone_lines.append(i)

        # Only flag if there are many clones — a signal of design issues
        if len(clone_lines) >= 5:
            findings.append(
                Finding(
                    severity=self.severity,
                    category=self.category,
                    title=f"Excessive `.clone()` usage ({len(clone_lines)} occurrences)",
                    description=(
                        f"Found {len(clone_lines)} `.clone()` calls. Frequent cloning may indicate "
                        "ownership/lifetime design issues and adds unnecessary heap allocations."
                    ),
                    suggestion=(
                        "Consider using references (`&T`), `Rc<T>`/`Arc<T>` for shared ownership, "
                        "or redesigning the data flow to avoid copies."
                    ),
                    confidence=0.70,
                )
            )
        return findings


class RustExpectWithoutMessageRule(Rule):
    """RS005 — .expect() without a descriptive message makes panics hard to diagnose."""

    id = "RS005"
    name = ".expect() without descriptive message"
    severity = Severity.LOW
    category = Category.QUALITY
    languages = [Language.RUST]

    # .expect("") or .expect("error") etc. — very short or empty messages
    _pattern = re.compile(r'\.expect\s*\(\s*"([^"]{0,10})"\s*\)')

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            m = self._pattern.search(line)
            if m:
                msg = m.group(1)
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title=f'`.expect("{msg}")` — message too vague',
                        description=(
                            f"Line {i}: `.expect()` with a short/empty message produces "
                            "an unhelpful panic message that makes debugging harder."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            'Use a descriptive message explaining what was expected: '
                            '`.expect("config file must be readable at startup")`'
                        ),
                        confidence=0.75,
                    )
                )
        return findings


ALL_RULES: list[Rule] = [
    RustUnwrapRule(),
    RustUnsafeBlockRule(),
    RustTodoMacroRule(),
    RustCloneOveruseRule(),
    RustExpectWithoutMessageRule(),
]
