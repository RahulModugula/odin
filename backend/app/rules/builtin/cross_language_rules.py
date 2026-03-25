"""Language-agnostic deterministic rules."""

from __future__ import annotations

import re

from app.models.enums import Category, Language, Severity
from app.models.schemas import Finding
from app.rules.engine import Rule


class TodoFixmeRule(Rule):
    id = "CL001"
    name = "TODO/FIXME/HACK comment"
    severity = Severity.INFO
    category = Category.QUALITY
    languages = list(Language)

    _pattern = re.compile(
        r"#.*\b(TODO|FIXME|HACK|XXX|BUG)\b|//.*\b(TODO|FIXME|HACK|XXX|BUG)\b",
        re.IGNORECASE,
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
            m = self._pattern.search(line)
            if m:
                keyword = (m.group(1) or m.group(2) or "TODO").upper()
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title=f"{keyword} comment found",
                        description=(
                            f"Line {i}: Unresolved {keyword} comment indicates incomplete work."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Address the issue or create a tracked ticket and remove the comment."
                        ),
                        confidence=0.95,
                    )
                )
        return findings


class LargeFileRule(Rule):
    id = "CL002"
    name = "File too large"
    severity = Severity.MEDIUM
    category = Category.QUALITY
    languages = list(Language)

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        lines = code.count("\n") + 1
        if lines > 500:
            return [
                Finding(
                    severity=Severity.HIGH if lines > 1000 else self.severity,
                    category=self.category,
                    title=f"File is very large ({lines} lines)",
                    description=(
                        f"This file has {lines} lines. Large files are hard to navigate "
                        "and often violate the Single Responsibility Principle."
                    ),
                    suggestion="Split into smaller modules with focused responsibilities.",
                    confidence=0.95,
                )
            ]
        return []


class MagicNumberRule(Rule):
    id = "CL003"
    name = "Magic number"
    severity = Severity.LOW
    category = Category.QUALITY
    languages = list(Language)

    # Commonly acceptable literals that need no named constant
    _ALLOWED = {0, 1, -1, 2, 10, 100, 1000}
    _pattern = re.compile(r'(?<!["\'\w.])(\d{3,})\b(?!["\'])')

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
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                continue
            if "import" in stripped or '"""' in stripped or "'''" in stripped:
                continue
            for m in self._pattern.finditer(line):
                val = int(m.group(1))
                if val in self._ALLOWED:
                    continue
                context = line[max(0, m.start() - 20) : m.end() + 20].lower()
                if any(
                    w in context
                    for w in ["status", "port", "timeout", "retry", "version", "code", "http"]
                ):
                    continue
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title=f"Magic number: {val}",
                        description=(
                            f"Line {i}: Unexplained numeric literal `{val}`. "
                            "Magic numbers make code hard to understand."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=f"Extract to a named constant: `MAX_ITEMS = {val}`",
                        confidence=0.7,
                    )
                )
        return findings


class HardcodedCredentialsRule(Rule):
    id = "CL004"
    name = "Hardcoded credential pattern"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = list(Language)

    _PATTERNS = [
        re.compile(r'(?i)password\s*[=:]\s*["\'][^"\']{6,}["\']'),
        re.compile(r'(?i)secret\s*[=:]\s*["\'][^"\']{6,}["\']'),
        re.compile(r'(?i)api[_-]?key\s*[=:]\s*["\'][^"\']{8,}["\']'),
        re.compile(r'(?i)token\s*[=:]\s*["\'][^"\']{8,}["\']'),
    ]

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
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                continue
            if any(skip in line for skip in ["os.environ", "process.env", "getenv", "config."]):
                continue
            for pattern in self._PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            title="Hardcoded credential detected",
                            description=f"Line {i}: A credential appears to be hardcoded. CWE-798.",
                            line_start=i,
                            line_end=i,
                            suggestion="Use environment variables or a secrets manager.",
                            confidence=0.85,
                        )
                    )
                    break
        return findings


ALL_RULES: list[Rule] = [
    TodoFixmeRule(),
    LargeFileRule(),
    MagicNumberRule(),
    HardcodedCredentialsRule(),
]
