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
                            "Use `const` for values that don't change, `let` for those that do."
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

    # Flag debug-only calls; console.error/warn are legitimate in error handlers
    _pattern = re.compile(r"\bconsole\.(log|debug)\s*\(")

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
                        title="console.log() debug statement found",
                        description=f"Line {i}: Debug logging statement left in code.",
                        line_start=i,
                        line_end=i,
                        suggestion="Remove before production or replace with a structured logger.",
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

    _pattern = re.compile(r"\.(innerHTML|outerHTML)\s*=|dangerouslySetInnerHTML\s*=\s*\{")

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


class JWTMisuseRule(Rule):
    """JS005 — jwt.decode() used without jwt.verify(), or missing algorithm whitelist."""

    id = "JS005"
    name = "Insecure JWT handling"
    severity = Severity.HIGH
    category = Category.SECURITY
    languages = [Language.JAVASCRIPT, Language.TYPESCRIPT]

    _DECODE_NO_VERIFY = re.compile(r"\bjwt\.decode\s*\(")
    _VERIFY = re.compile(r"\bjwt\.verify\s*\(")
    _ALGORITHMS_OPT = re.compile(r"algorithms\s*:\s*\[")

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

            # jwt.decode() without a nearby jwt.verify() is dangerous
            if self._DECODE_NO_VERIFY.search(line) and not self._VERIFY.search(code):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="`jwt.decode()` skips signature verification",
                        description=(
                            f"Line {i}: `jwt.decode()` does not verify the token signature. "
                            "Any claims in the payload can be forged. CWE-347."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Use `jwt.verify(token, secret, {{ algorithms: ['HS256'] }})` "
                            "instead. Never trust payload data from `jwt.decode()`."
                        ),
                        confidence=0.9,
                    )
                )

            # jwt.verify() without algorithms option is vulnerable to algorithm confusion
            if self._VERIFY.search(line) and not self._ALGORITHMS_OPT.search(code):
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category=self.category,
                        title="JWT verify missing explicit `algorithms` whitelist",
                        description=(
                            f"Line {i}: `jwt.verify()` without `algorithms: ['RS256']` (or "
                            "similar) allows algorithm-confusion attacks — an attacker can "
                            "switch to `alg:none` or HS256 with the public key. CWE-347."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Always specify `{{ algorithms: ['RS256'] }}` (or your actual "
                            "algorithm) in the options object passed to `jwt.verify()`."
                        ),
                        confidence=0.75,
                    )
                )

        return findings


class PrototypePollutionRule(Rule):
    """JS006 — recursive merge / path-based assignment without __proto__ guard."""

    id = "JS006"
    name = "Prototype pollution risk"
    severity = Severity.HIGH
    category = Category.SECURITY
    languages = [Language.JAVASCRIPT, Language.TYPESCRIPT]

    # Recursive merge pattern: target[key] = source[key] inside a function
    _MERGE_PATTERN = re.compile(r"(target|dest|obj|result)\[(\w+)\]\s*=\s*(source|src|from)\[")
    # Guard: an if-statement that checks for __proto__ / constructor / prototype keys
    _PROTO_GUARD = re.compile(
        r"===\s*['\"]__proto__['\"]|===\s*['\"]constructor['\"]|"
        r"===\s*['\"]prototype['\"]|"
        r"if\s*\([^)]*(__proto__|constructor)[^)]*\)|"
        r"Object\.hasOwn\(|hasOwnProperty\s*\("
    )

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Skip if the code already has prototype guards
        if self._PROTO_GUARD.search(code):
            return []

        for i, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            if self._MERGE_PATTERN.search(line):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="Prototype pollution — unguarded object merge",
                        description=(
                            f"Line {i}: Object merge copies properties without checking for "
                            "`__proto__`, `constructor`, or `prototype` keys. An attacker can "
                            "poison `Object.prototype` for all objects in the process. CWE-1321."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Add a key guard: `if (key === '__proto__' || key === 'constructor' "
                            "|| key === 'prototype') continue;`. "
                            "Or use `Object.assign({}, ...)` with structuredClone for deep copies."
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
    JWTMisuseRule(),
    PrototypePollutionRule(),
]
