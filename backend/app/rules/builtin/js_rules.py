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


class NonNullAssertionRule(Rule):
    """TS002 — Overuse of the non-null assertion operator `!` bypasses TypeScript's type safety."""

    id = "TS002"
    name = "Non-null assertion operator overuse"
    severity = Severity.MEDIUM
    category = Category.QUALITY
    languages = [Language.TYPESCRIPT]

    # Match trailing `!` that is used as a non-null assertion (not `!=` or `!==`)
    _NON_NULL = re.compile(r"\w+!\s*(?:[.\[;,)\s]|$)")
    # False positive guard: allow `!` in boolean conditions / template literals
    _BOOLEAN_OP = re.compile(r"(?:if|while|&&|\|\|)\s*\(?\s*!\w")

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        assertion_count = 0
        assertion_lines: list[int] = []

        for i, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if self._NON_NULL.search(line) and not self._BOOLEAN_OP.search(line):
                assertion_count += 1
                assertion_lines.append(i)

        # Only flag if there are multiple assertions in the same file
        # (one or two is fine; many suggests systemic avoidance of type checking)
        if assertion_count >= 3:
            for line_no in assertion_lines:
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="Non-null assertion operator (`!`) used",
                        description=(
                            f"Line {line_no}: The non-null assertion operator `!` tells TypeScript "
                            "to ignore null/undefined. With {assertion_count} assertions in this file, "
                            "this suggests the types are wrong rather than the values. "
                            "Each `!` is a potential runtime TypeError."
                        ),
                        line_start=line_no,
                        line_end=line_no,
                        suggestion=(
                            "Use optional chaining (`?.`) and nullish coalescing (`??`) to handle "
                            "null/undefined safely, or fix the upstream type so it doesn't include null."
                        ),
                        confidence=0.72,
                    )
                )
        return findings


class AsyncWithoutAwaitRule(Rule):
    """JS005 — async function that never uses await is misleading and adds overhead."""

    id = "JS005"
    name = "async function without await"
    severity = Severity.LOW
    category = Category.QUALITY
    languages = [Language.JAVASCRIPT, Language.TYPESCRIPT]

    _ASYNC_FUNC = re.compile(r"\basync\s+(?:function\s*\w*\s*\(|(?:\(|[\w]+)\s*=>)")
    _AWAIT = re.compile(r"\bawait\b")

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        """Flag async functions that contain no await expression."""
        findings: list[Finding] = []
        lines = code.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("//", "*")):
                continue
            if not self._ASYNC_FUNC.search(line):
                continue

            # Scan forward up to 30 lines for an await
            window_end = min(len(lines), i + 30)
            window = "\n".join(lines[i - 1 : window_end])
            if not self._AWAIT.search(window):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="`async` function with no `await`",
                        description=(
                            f"Line {i}: Function declared `async` but contains no `await` in the "
                            "next 30 lines. An async function without await returns a resolved Promise "
                            "immediately — callers that `await` it incur a microtask overhead for no reason."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Remove `async` if the function is synchronous, or add the missing `await` "
                            "if an async operation was forgotten."
                        ),
                        confidence=0.65,
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
    NonNullAssertionRule(),
    AsyncWithoutAwaitRule(),
]
