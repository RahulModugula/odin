"""Cross-language performance and efficiency rules."""

from __future__ import annotations

import re

from app.models.enums import Category, Language, Severity
from app.models.schemas import Finding
from app.rules.engine import Rule


class RegexInLoopRule(Rule):
    """PERF001 — Compiling a regex inside a loop is expensive."""

    id = "PERF001"
    name = "Regex compiled inside loop"
    severity = Severity.MEDIUM
    category = Category.PERFORMANCE
    languages = [Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT]

    # Python: re.compile / re.match / re.search inside a for/while block
    _PY_REGEX = re.compile(r"\bre\.(compile|match|search|findall|sub|fullmatch)\s*\(")
    _JS_REGEX = re.compile(r"\bnew\s+RegExp\s*\(")
    _LOOP = re.compile(r"\b(for|while)\b")

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        lines = code.splitlines()
        nesting = 0

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            if self._LOOP.search(stripped):
                nesting += 1

            if nesting > 0:
                if language == Language.PYTHON and self._PY_REGEX.search(line):
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            title="Regex compiled inside loop",
                            description=(
                                f"Line {i}: `re.compile()` or similar called inside a loop. "
                                "Every iteration compiles the regex pattern, adding unnecessary CPU work."
                            ),
                            line_start=i,
                            line_end=i,
                            suggestion=(
                                "Compile the regex once before the loop: "
                                "`pattern = re.compile(r'...')` then use `pattern.search(text)` inside."
                            ),
                            confidence=0.82,
                        )
                    )
                elif language in (
                    Language.JAVASCRIPT,
                    Language.TYPESCRIPT,
                ) and self._JS_REGEX.search(line):
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            title="RegExp instantiated inside loop",
                            description=(
                                f"Line {i}: `new RegExp(...)` called inside a loop. "
                                "Each iteration compiles the pattern unnecessarily."
                            ),
                            line_start=i,
                            line_end=i,
                            suggestion=(
                                "Move `new RegExp(...)` outside the loop or use a regex literal "
                                "(`/pattern/`) which is cached by the engine."
                            ),
                            confidence=0.82,
                        )
                    )

            # Rough dedent tracking for Python
            if (
                language == Language.PYTHON
                and nesting > 0
                and stripped
                and not stripped.endswith(":")
            ):
                pass  # simple approximation; tree-sitter can do better

        return findings


class StringConcatInLoopRule(Rule):
    """PERF002 — String concatenation in a loop is O(n²) due to immutable strings."""

    id = "PERF002"
    name = "String concatenation in loop"
    severity = Severity.MEDIUM
    category = Category.PERFORMANCE
    languages = [Language.PYTHON, Language.JAVA]

    _PY_CONCAT = re.compile(r'\b\w+\s*\+=\s*["\']|\b\w+\s*=\s*\w+\s*\+\s*["\']')
    _JAVA_CONCAT = re.compile(r'\b\w+\s*\+=\s*"|\bString\s+\w+\s*=\s*\w+\s*\+\s*"')
    _LOOP = re.compile(r"\b(for|while)\b")

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        lines = code.splitlines()
        in_loop = False

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            if self._LOOP.search(stripped):
                in_loop = True

            if in_loop:
                pattern = self._PY_CONCAT if language == Language.PYTHON else self._JAVA_CONCAT
                if pattern.search(line):
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            title="String concatenation inside loop (O(n²))",
                            description=(
                                f"Line {i}: Building a string with `+=` inside a loop creates a "
                                "new string object on every iteration — O(n²) time and O(n²) memory."
                            ),
                            line_start=i,
                            line_end=i,
                            suggestion=(
                                "Collect parts in a list and join at the end: "
                                "`parts.append(s)` then `''.join(parts)` (Python) or "
                                "`StringBuilder` (Java)."
                            ),
                            confidence=0.80,
                        )
                    )

        return findings


class WeakCryptoHashRule(Rule):
    """PERF003 (security) — MD5 and SHA-1 are cryptographically broken."""

    id = "PERF003"
    name = "Weak cryptographic hash function (MD5 / SHA-1)"
    severity = Severity.HIGH
    category = Category.SECURITY
    languages = list(Language)

    _PATTERNS = [
        re.compile(r"\b(md5|MD5)\b"),
        re.compile(r'\bhashlib\.new\s*\(\s*["\']md5["\']'),
        re.compile(r'\bhashlib\.new\s*\(\s*["\']sha1["\']'),
        re.compile(r"\bhashlib\.md5\s*\("),
        re.compile(r"\bhashlib\.sha1\s*\("),
        re.compile(r"\bMessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-1|SHA1)\""),
        re.compile(r"\bcrypto\.createHash\s*\(\s*['\"]md5['\"]"),
        re.compile(r"\bcrypto\.createHash\s*\(\s*['\"]sha1['\"]"),
    ]
    # Only flag in security contexts (passwords, signing, tokens)
    _SECURITY_CTX = re.compile(
        r"(?i)(password|passwd|signature|sign|hmac|auth|token|credential|integrity)",
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
        lines = code.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                continue
            for pat in self._PATTERNS:
                if pat.search(line):
                    # Check surrounding context for security-sensitive use
                    window_start = max(0, i - 10)
                    window_end = min(len(lines), i + 5)
                    window = "\n".join(lines[window_start:window_end])
                    # Always flag if in a security context; also flag bare MD5 imports
                    if (
                        self._SECURITY_CTX.search(window)
                        or "hashlib.md5" in line
                        or "MessageDigest" in line
                    ):
                        findings.append(
                            Finding(
                                severity=self.severity,
                                category=self.category,
                                title="Weak cryptographic hash: MD5 or SHA-1",
                                description=(
                                    f"Line {i}: MD5 and SHA-1 are cryptographically broken — "
                                    "collision attacks are practical (SHA-1 broken 2017, MD5 2004). "
                                    "CWE-327, CWE-328."
                                ),
                                line_start=i,
                                line_end=i,
                                suggestion=(
                                    "Use SHA-256 or SHA-3: `hashlib.sha256()` (Python), "
                                    '`MessageDigest.getInstance("SHA-256")` (Java), '
                                    "`crypto.createHash('sha256')` (Node.js). "
                                    "For passwords, use bcrypt, scrypt, or Argon2."
                                ),
                                confidence=0.88,
                            )
                        )
                        break
        return findings


class PathTraversalRule(Rule):
    """PERF004 (security) — User input used to construct file paths."""

    id = "PERF004"
    name = "Potential path traversal"
    severity = Severity.HIGH
    category = Category.SECURITY
    languages = [
        Language.PYTHON,
        Language.JAVASCRIPT,
        Language.TYPESCRIPT,
        Language.JAVA,
        Language.GO,
    ]

    _FILE_OPS = re.compile(
        r"\b(open|os\.path\.(join|exists|isfile)|pathlib\.Path|"
        r"fs\.(readFile|writeFile|readFileSync|writeFileSync|existsSync|createReadStream)|"
        r"new\s+File\s*\(|Files\.(read|write|copy|move)|"
        r"os\.Open|os\.Create|ioutil\.(ReadFile|WriteFile))\s*\("
    )
    _USER_INPUT = re.compile(
        r"(?i)(request\.(args|form|json|params|query|body|get_json)|"
        r"req\.(body|query|params)|"
        r"input\s*\(|sys\.argv|os\.environ\.get|getenv|"
        r"ctx\.Param|c\.Query|r\.FormValue)"
    )

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
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            if not self._FILE_OPS.search(line):
                continue
            # Check 15-line window for user input sources
            window_start = max(0, i - 15)
            window = "\n".join(lines[window_start:i])
            if self._USER_INPUT.search(window):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="Potential path traversal — user input in file path",
                        description=(
                            f"Line {i}: A file operation uses a path that may originate from "
                            "user input. `../` sequences can escape the intended directory. CWE-22."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Validate and sanitize file paths: use `os.path.realpath()` and verify "
                            "the result starts with the allowed base directory. "
                            "Never pass raw user input to file operations."
                        ),
                        confidence=0.78,
                    )
                )
        return findings


class SensitiveDataLoggingRule(Rule):
    """PERF005 — Logging sensitive fields (passwords, tokens, PII) leaks data."""

    id = "PERF005"
    name = "Sensitive data in log statement"
    severity = Severity.HIGH
    category = Category.SECURITY
    languages = list(Language)

    _LOG_CALL = re.compile(
        r"\b(log|logger|logging|console)\.(debug|info|warn|warning|error|critical|log)\s*\(|"
        r"\bprint\s*\(|"
        r"\bSystem\.out\.(print|println)\s*\(|"
        r"\bfmt\.(Print|Println|Printf)\s*\("
    )
    _SENSITIVE = re.compile(
        r"(?i)(password|passwd|secret|api_key|apikey|token|auth|credential|"
        r"ssn|social.?security|credit.?card|cvv|pan\b|private.?key|"
        r"access.?key|bearer)",
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
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            if self._LOG_CALL.search(line) and self._SENSITIVE.search(line):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="Sensitive data logged — potential data exposure",
                        description=(
                            f"Line {i}: A log statement appears to include sensitive data "
                            "(password, token, key, etc.). Logs are often stored unencrypted "
                            "and accessible to many people. CWE-532."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Redact or mask sensitive fields before logging: "
                            '`log.info("User authenticated", user_id=user.id)` — '
                            "never log passwords, tokens, or PII."
                        ),
                        confidence=0.82,
                    )
                )
        return findings


ALL_RULES: list[Rule] = [
    RegexInLoopRule(),
    StringConcatInLoopRule(),
    WeakCryptoHashRule(),
    PathTraversalRule(),
    SensitiveDataLoggingRule(),
]
