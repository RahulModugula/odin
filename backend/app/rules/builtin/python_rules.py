"""Python-specific deterministic rules."""

from __future__ import annotations

import re

from app.models.enums import Category, Language, Severity
from app.models.schemas import Finding
from app.rules.engine import Rule


class BareExceptRule(Rule):
    id = "PY001"
    name = "Bare except clause"
    severity = Severity.HIGH
    category = Category.QUALITY
    languages = [Language.PYTHON]

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
            if stripped == "except:" or stripped.startswith("except:  ") or stripped.startswith(
                "except: #"
            ):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="Bare except clause catches all exceptions",
                        description=(
                            f"Line {i}: `except:` catches ALL exceptions including "
                            "SystemExit, KeyboardInterrupt, and GeneratorExit. "
                            "This silently swallows critical errors."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Catch specific exception types: `except ValueError:` "
                            "or `except (TypeError, ValueError):`"
                        ),
                        confidence=0.95,
                    )
                )
        return findings


class MutableDefaultArgRule(Rule):
    id = "PY002"
    name = "Mutable default argument"
    severity = Severity.HIGH
    category = Category.QUALITY
    languages = [Language.PYTHON]

    _pattern = re.compile(r"def\s+\w+\s*\([^)]*=\s*(\[\s*\]|\{\s*\}|\[\]|\{\})[^)]*\)")

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(code.splitlines(), 1):
            if self._pattern.search(line):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="Mutable default argument",
                        description=(
                            f"Line {i}: Using a mutable object (list `[]` or dict `{{}}`) "
                            "as a default argument. The same object is shared across all calls."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Use `None` as default and initialize inside the function: "
                            "`def foo(x=None): x = x or []`"
                        ),
                        confidence=0.9,
                    )
                )
        return findings


class EvalUsageRule(Rule):
    id = "PY003"
    name = "Use of eval() or exec()"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = [Language.PYTHON]

    _pattern = re.compile(r"\b(eval|exec)\s*\(")

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
            if stripped.startswith("#"):
                continue
            m = self._pattern.search(line)
            if m:
                func = m.group(1)
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title=f"Dangerous use of `{func}()`",
                        description=(
                            f"Line {i}: `{func}()` executes arbitrary code and is a major "
                            "security risk if any input is user-controlled. CWE-95."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Remove eval/exec. Use a data structure (dict, function map) "
                            "instead of dynamic code execution."
                        ),
                        confidence=0.9,
                    )
                )
        return findings


class HardcodedSecretsRule(Rule):
    id = "PY004"
    name = "Hardcoded secret or credential"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = [Language.PYTHON]

    _SECRET_PATTERNS = [
        re.compile(
            r"(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth_token|access_token)"
            r'\s*=\s*["\'][^"\']{8,}["\']'
        ),
        re.compile(
            r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*["\'][^"\']+["\']'
        ),
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),  # OpenAI-style keys
        re.compile(r"ghp_[a-zA-Z0-9]{36}"),  # GitHub tokens
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
            if stripped.startswith("#"):
                continue
            for pattern in self._SECRET_PATTERNS:
                if pattern.search(line):
                    # Avoid false positives from env vars and config reads
                    if "os.environ" in line or "getenv" in line or "os.getenv" in line:
                        continue
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            title="Hardcoded credential or secret",
                            description=f"Line {i}: Credential or secret appears to be hardcoded. CWE-798.",  # noqa: E501
                            line_start=i,
                            line_end=i,
                            suggestion=(
                                "Use environment variables: `os.environ['MY_SECRET']` "
                                "or a secrets manager."
                            ),
                            confidence=0.85,
                        )
                    )
                    break
        return findings


class SqlStringFormattingRule(Rule):
    id = "PY005"
    name = "SQL injection via string formatting"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = [Language.PYTHON]

    _sql_pattern = re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s")
    _format_pattern = re.compile(r"(%s|%d|\{[^}]*\}|f[\"'].*\{)")

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        lines = code.splitlines()
        for i, line in enumerate(lines, 1):
            if self._sql_pattern.search(line) and self._format_pattern.search(line):
                prev_line = lines[i - 2] if i > 1 else ""
                if "execute" in line or "query" in line.lower() or "execute" in prev_line:
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            title="Potential SQL injection via string formatting",
                            description=(
                                f"Line {i}: SQL query appears to be built using string "
                                "formatting. CWE-89."
                            ),
                            line_start=i,
                            line_end=i,
                            suggestion=(
                                "Use parameterized queries: "
                                "`cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`"
                            ),
                            confidence=0.8,
                        )
                    )
        return findings


class ComplexityThresholdRule(Rule):
    id = "PY006"
    name = "High cyclomatic complexity"
    severity = Severity.MEDIUM
    category = Category.QUALITY
    languages = [Language.PYTHON]

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if structure is not None and structure.metrics.cyclomatic_complexity > 10:  # type: ignore[union-attr]
            cc = structure.metrics.cyclomatic_complexity  # type: ignore[union-attr]
            findings.append(
                Finding(
                    severity=Severity.HIGH if cc > 20 else self.severity,
                    category=self.category,
                    title=f"High cyclomatic complexity: {cc}",
                    description=(
                        f"File has a cyclomatic complexity of {cc}. "
                        "Values above 10 indicate hard-to-test and hard-to-maintain code."
                    ),
                    suggestion=(
                        "Break complex functions into smaller, focused functions. "
                        "Aim for complexity < 10."
                    ),
                    confidence=0.95,
                )
            )
        return findings


class FunctionLengthRule(Rule):
    id = "PY007"
    name = "Overly long function"
    severity = Severity.MEDIUM
    category = Category.QUALITY
    languages = [Language.PYTHON]

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if structure is None:
            return findings
        for func in structure.functions:  # type: ignore[union-attr]
            if func.body_length > 50:
                findings.append(
                    Finding(
                        severity=Severity.HIGH if func.body_length > 100 else self.severity,
                        category=self.category,
                        title=f"Function `{func.name}` is too long ({func.body_length} lines)",
                        description=(
                            f"Function `{func.name}` (lines {func.line_start}-{func.line_end}) "
                            f"has {func.body_length} lines. "
                            "Long functions are hard to understand and test."
                        ),
                        line_start=func.line_start,
                        line_end=func.line_end,
                        suggestion=(
                            "Break into smaller functions with single responsibilities. "
                            "Aim for < 50 lines."
                        ),
                        confidence=0.9,
                    )
                )
        return findings


class NestingDepthRule(Rule):
    id = "PY008"
    name = "Excessive nesting depth"
    severity = Severity.MEDIUM
    category = Category.QUALITY
    languages = [Language.PYTHON]

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if structure is not None and structure.metrics.max_nesting_depth > 4:  # type: ignore[union-attr]
            depth = structure.metrics.max_nesting_depth  # type: ignore[union-attr]
            findings.append(
                Finding(
                    severity=Severity.HIGH if depth > 6 else self.severity,
                    category=self.category,
                    title=f"Excessive nesting depth: {depth} levels",
                    description=(
                        f"Code has {depth} levels of nesting. "
                        "Deep nesting makes code hard to read and test."
                    ),
                    suggestion=(
                        "Use early returns ('guard clauses'), extract nested blocks into "
                        "functions, or use flat data structures."
                    ),
                    confidence=0.9,
                )
            )
        return findings


class MissingTypeHintsRule(Rule):
    id = "PY009"
    name = "Missing type hints on public function"
    severity = Severity.LOW
    category = Category.QUALITY
    languages = [Language.PYTHON]

    _pattern = re.compile(r"^def\s+([a-zA-Z][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*:")

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(code.splitlines(), 1):
            m = self._pattern.match(line.strip())
            if m:
                func_name = m.group(1)
                if func_name.startswith("_"):
                    continue  # skip private / dunder methods
                if "->" not in line and ":" in line:
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            title=f"Missing return type hint on `{func_name}`",
                            description=(
                                f"Line {i}: Public function `{func_name}` "
                                "has no return type annotation."
                            ),
                            line_start=i,
                            line_end=i,
                            suggestion=(
                                f"Add a return type hint: `def {func_name}(...) -> ReturnType:`"
                            ),
                            confidence=0.7,
                        )
                    )
        return findings


ALL_RULES: list[Rule] = [
    BareExceptRule(),
    MutableDefaultArgRule(),
    EvalUsageRule(),
    HardcodedSecretsRule(),
    SqlStringFormattingRule(),
    ComplexityThresholdRule(),
    FunctionLengthRule(),
    NestingDepthRule(),
    MissingTypeHintsRule(),
]
