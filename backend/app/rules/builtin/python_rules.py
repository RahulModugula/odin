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
            if (
                stripped == "except:"
                or stripped.startswith("except:  ")
                or stripped.startswith("except: #")
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
        re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*["\'][^"\']+["\']'),
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
        if structure is not None and structure.metrics.max_nesting_depth > 6:  # type: ignore[union-attr]
            depth = structure.metrics.max_nesting_depth  # type: ignore[union-attr]
            findings.append(
                Finding(
                    severity=Severity.HIGH if depth > 8 else self.severity,
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


class UnsafeDeserializationRule(Rule):
    """PY010 — pickle.loads / yaml.load on any input is a code-execution risk."""

    id = "PY010"
    name = "Unsafe deserialization"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = [Language.PYTHON]

    _PATTERNS = [
        re.compile(r"\bpickle\.loads?\s*\("),
        re.compile(r"\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)"),
        re.compile(r"\bshelve\.open\s*\("),
        re.compile(r"\bjsonpickle\.decode\s*\("),
        re.compile(r"\bdill\.loads?\s*\("),
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
            for pat in self._PATTERNS:
                if pat.search(line):
                    name = (
                        "pickle.loads"
                        if "pickle" in line
                        else pat.pattern.split(r"\b")[1].split(r"\s")[0]
                    )
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            title="Unsafe deserialization (pickle / yaml.load)",
                            description=(
                                f"Line {i}: Deserializing untrusted data with `{name}` allows "
                                "arbitrary code execution. CWE-502."
                            ),
                            line_start=i,
                            line_end=i,
                            suggestion=(
                                "Use `json.loads` for data exchange. If you must use pickle, "
                                "only deserialize data you signed with HMAC. For YAML use "
                                "`yaml.safe_load()`."
                            ),
                            confidence=0.9,
                        )
                    )
                    break
        return findings


class CommandInjectionRule(Rule):
    """PY011 — subprocess / os.system with shell=True and string interpolation."""

    id = "PY011"
    name = "OS command injection"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = [Language.PYTHON]

    # shell=True with a non-literal command string
    _SHELL_TRUE = re.compile(r"\bsubprocess\.(run|call|Popen|check_output|check_call)\s*\(")
    _SHELL_FLAG = re.compile(r"shell\s*=\s*True")
    _OS_SYSTEM = re.compile(r"\bos\.(system|popen)\s*\(")
    _INTERP = re.compile(r'["\'].*\{|f["\']|%\s*[a-zA-Z(]|\+\s*[a-zA-Z_]')

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
            if stripped.startswith("#"):
                continue

            # os.system / os.popen with any non-literal arg
            if self._OS_SYSTEM.search(line) and self._INTERP.search(line):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="OS command injection via os.system / os.popen",
                        description=(
                            f"Line {i}: `os.system`/`os.popen` with a dynamic string argument "
                            "allows shell metacharacters to inject commands. CWE-78."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Use `subprocess.run([...])` with a list (no `shell=True`) "
                            "to avoid shell interpretation."
                        ),
                        confidence=0.88,
                    )
                )
                continue

            # subprocess(..., shell=True) — check this line and the next 5 for shell=True
            if self._SHELL_TRUE.search(line):
                window = "\n".join(lines[i - 1 : min(i + 5, len(lines))])
                if self._SHELL_FLAG.search(window) and self._INTERP.search(window):
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            title="Command injection via subprocess shell=True",
                            description=(
                                f"Line {i}: `subprocess` called with `shell=True` and a dynamic "
                                "command string. Shell metacharacters in user input will be "
                                "interpreted by the shell. CWE-78."
                            ),
                            line_start=i,
                            line_end=i,
                            suggestion=(
                                "Pass a list to subprocess.run: "
                                "`subprocess.run(['ping', '-c', '1', host])` — never `shell=True` "
                                "with user-controlled input."
                            ),
                            confidence=0.9,
                        )
                    )

        return findings


class InsecureRandomRule(Rule):
    """PY012 — random module used in a security-sensitive context."""

    id = "PY012"
    name = "Insecure PRNG for security token"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    languages = [Language.PYTHON]

    _RANDOM_CALL = re.compile(
        r"\brandom\.(random|randint|randrange|choice|choices|sample|uniform)\s*\("
    )
    # Function/variable names that suggest security-sensitive use
    _SENSITIVE_CTX = re.compile(
        r"(?i)(token|secret|password|passwd|session|otp|nonce|salt|csrf|key|auth|pin|code)",
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
            if stripped.startswith("#") or not self._RANDOM_CALL.search(line):
                continue

            # Check surrounding 10-line window for security-context names
            window_start = max(0, i - 6)
            window_end = min(len(lines), i + 5)
            window = "\n".join(lines[window_start:window_end])

            if self._SENSITIVE_CTX.search(window):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="Cryptographically weak PRNG used for security value",
                        description=(
                            f"Line {i}: `random` module functions use the Mersenne Twister "
                            "which is not cryptographically secure. After ~624 observations "
                            "the internal state is fully recoverable. CWE-338."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Use `secrets.token_hex(32)`, `secrets.token_urlsafe()`, or "
                            "`os.urandom()` for security-sensitive random values."
                        ),
                        confidence=0.8,
                    )
                )

        return findings


class XXERule(Rule):
    """PY013 — lxml / xml parsers configured to resolve external entities."""

    id = "PY013"
    name = "XML External Entity (XXE) injection"
    severity = Severity.HIGH
    category = Category.SECURITY
    languages = [Language.PYTHON]

    _XXE_PATTERNS = [
        re.compile(r"XMLParser\s*\(.*resolve_entities\s*=\s*True"),
        re.compile(r"etree\.parse\s*\((?!.*defusedxml)"),
        re.compile(r"xml\.etree\.ElementTree\.(parse|fromstring)\s*\("),
        re.compile(r"minidom\.parse\s*\("),
        re.compile(r"sax\.parse\s*\("),
    ]
    _DEFUSED = re.compile(r"defusedxml|no_network\s*=\s*True|resolve_entities\s*=\s*False")

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # If defusedxml is imported or resolve_entities=False is present, skip
        if self._DEFUSED.search(code):
            return []

        for i, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pat in self._XXE_PATTERNS:
                if pat.search(line):
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            title="Potential XML External Entity (XXE) injection",
                            description=(
                                f"Line {i}: XML parser may resolve external entities, enabling "
                                "file disclosure (`file:///etc/passwd`) and SSRF. CWE-611."
                            ),
                            line_start=i,
                            line_end=i,
                            suggestion=(
                                "Use `defusedxml` library, or set "
                                "`XMLParser(resolve_entities=False, no_network=True)`. "
                                "Standard `xml.etree.ElementTree` does not block "
                                "billion-laughs DoS attacks."
                            ),
                            confidence=0.75,
                        )
                    )
                    break

        return findings


class SSRFRule(Rule):
    """PY014 — HTTP request with a user-controlled URL (potential SSRF)."""

    id = "PY014"
    name = "Potential Server-Side Request Forgery (SSRF)"
    severity = Severity.HIGH
    category = Category.SECURITY
    languages = [Language.PYTHON]

    _HTTP_CALL = re.compile(
        r"\b(requests\.(get|post|put|delete|patch|head|request)|"
        r"urllib\.request\.urlopen|"
        r"httpx\.(get|post|put|delete|patch|AsyncClient)|"
        r"aiohttp\.ClientSession\(\))\s*\("
    )
    # Input sources that indicate user-controlled data
    _USER_INPUT = re.compile(
        r"(?i)(request\.(args|form|json|data|get_json|cookies|headers|values|params)|"
        r"input\s*\(|sys\.argv|os\.environ|getenv|flask\.request|"
        r"form\[|params\[|body\[)"
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
            if stripped.startswith("#") or not self._HTTP_CALL.search(line):
                continue

            # Check 15-line window before the HTTP call for user-input sources
            window_start = max(0, i - 15)
            window = "\n".join(lines[window_start:i])

            if self._USER_INPUT.search(window):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="Potential SSRF — HTTP request with user-controlled URL",
                        description=(
                            f"Line {i}: An HTTP request is made with a URL that may originate "
                            "from user input. An attacker can point this at internal services "
                            "or cloud metadata endpoints (169.254.169.254). CWE-918."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Validate the URL against an explicit allowlist of hosts/schemes. "
                            "Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x). "
                            "Never pass raw user input to an HTTP client."
                        ),
                        confidence=0.75,
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
    UnsafeDeserializationRule(),
    CommandInjectionRule(),
    InsecureRandomRule(),
    XXERule(),
    SSRFRule(),
]
