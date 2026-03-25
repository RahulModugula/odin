"""JavaScript/TypeScript deterministic rules."""

from __future__ import annotations

import re

from app.models.enums import Category, Language, Severity
from app.models.schemas import Finding
from app.rules.engine import Rule


class NoVarRule(Rule):
    id = "JS001"
    name = "Use of var instead of let/const"
    severity = Severity.LOW
    category = Category.QUALITY
    languages = [Language.JAVASCRIPT, Language.TYPESCRIPT]

    _pattern = re.compile(r"\bvar\s+\w+")

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
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if self._pattern.search(line):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="Use of `var` — prefer `let` or `const`",
                        description=(
                            f"Line {i}: `var` has function scope and hoisting behavior "
                            "that can cause subtle bugs."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Use `const` for values that don't change, "
                            "`let` for those that do."
                        ),
                        confidence=0.9,
                    )
                )
        return findings


class ConsoleLogRule(Rule):
    id = "JS002"
    name = "console.log() left in production code"
    severity = Severity.LOW
    category = Category.QUALITY
    languages = [Language.JAVASCRIPT, Language.TYPESCRIPT]

    _pattern = re.compile(r"\bconsole\.(log|debug|info|warn|error)\s*\(")

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
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if self._pattern.search(line):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="console.log() statement found",
                        description=f"Line {i}: Debug/logging statement left in code.",
                        line_start=i,
                        line_end=i,
                        suggestion="Remove or replace with a proper logging library.",
                        confidence=0.85,
                    )
                )
        return findings


class XSSPatternRule(Rule):
    id = "JS003"
    name = "Potential XSS via innerHTML or dangerouslySetInnerHTML"
    severity = Severity.HIGH
    category = Category.SECURITY
    languages = [Language.JAVASCRIPT, Language.TYPESCRIPT]

    _pattern = re.compile(
        r"\.(innerHTML|outerHTML)\s*=|dangerouslySetInnerHTML\s*=\s*\{"
    )

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
                        title="Potential XSS via unsafe HTML injection",
                        description=(
                            f"Line {i}: Direct HTML injection. If user input reaches "
                            "this, it is an XSS vulnerability. CWE-79."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Use textContent instead of innerHTML, or sanitize with "
                            "DOMPurify before inserting HTML."
                        ),
                        confidence=0.85,
                    )
                )
        return findings


class NoAnyTypeRule(Rule):
    id = "TS001"
    name = "TypeScript `any` type usage"
    severity = Severity.MEDIUM
    category = Category.QUALITY
    languages = [Language.TYPESCRIPT]

    _pattern = re.compile(r":\s*any\b|<any>|as\s+any\b")

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
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if self._pattern.search(line):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="TypeScript `any` type defeats type safety",
                        description=(
                            f"Line {i}: Using `any` disables TypeScript's "
                            "type checking for this variable."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Use a specific type, `unknown` with type narrowing, "
                            "or a generic type parameter."
                        ),
                        confidence=0.85,
                    )
                )
        return findings


class CallbackNestingRule(Rule):
    id = "JS004"
    name = "Deep callback nesting (callback hell)"
    severity = Severity.MEDIUM
    category = Category.QUALITY
    languages = [Language.JAVASCRIPT, Language.TYPESCRIPT]

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if structure is not None and structure.metrics.max_nesting_depth > 5:  # type: ignore[union-attr]
            depth = structure.metrics.max_nesting_depth  # type: ignore[union-attr]
            findings.append(
                Finding(
                    severity=self.severity,
                    category=self.category,
                    title=f"Deep callback nesting: {depth} levels",
                    description=(
                        f"Code has {depth} levels of nesting. "
                        "This is often a sign of callback hell."
                    ),
                    suggestion=(
                        "Refactor with async/await, Promises, or break into named functions."
                    ),
                    confidence=0.8,
                )
            )
        return findings


ALL_RULES: list[Rule] = [
    NoVarRule(),
    ConsoleLogRule(),
    XSSPatternRule(),
    NoAnyTypeRule(),
    CallbackNestingRule(),
]
