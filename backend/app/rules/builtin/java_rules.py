"""Java-specific deterministic rules."""

from __future__ import annotations

import re

from app.models.enums import Category, Language, Severity
from app.models.schemas import Finding
from app.rules.engine import Rule


class JavaSystemOutRule(Rule):
    """JA001 — System.out.println is not production-grade logging."""

    id = "JA001"
    name = "System.out.println in production code"
    severity = Severity.LOW
    category = Category.QUALITY
    languages = [Language.JAVA]

    _pattern = re.compile(r"\bSystem\.(out|err)\.(println|print|printf)\s*\(")

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
                        title="System.out.println() found — use a logging framework",
                        description=(
                            f"Line {i}: `System.out.println` is not structured, has no log levels, "
                            "and cannot be controlled at runtime."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Replace with SLF4J/Logback: "
                            "`private static final Logger log = LoggerFactory.getLogger(Foo.class);` "
                            'then `log.info("message");`'
                        ),
                        confidence=0.92,
                    )
                )
        return findings


class JavaRawTypeRule(Rule):
    """JA002 — Raw generic types (List, Map, Set) bypass type safety."""

    id = "JA002"
    name = "Raw generic type usage"
    severity = Severity.MEDIUM
    category = Category.QUALITY
    languages = [Language.JAVA]

    _pattern = re.compile(
        r"\b(List|Map|Set|Collection|Iterable|Iterator|Optional|Comparator|"
        r"ArrayList|HashMap|HashSet|LinkedList|TreeMap|TreeSet)\s+\w+\s*[=;(,]"
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
            if (
                stripped.startswith("//")
                or stripped.startswith("*")
                or stripped.startswith("import")
            ):
                continue
            m = self._pattern.search(line)
            if m:
                raw_type = m.group(1)
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title=f"Raw type `{raw_type}` used without type parameter",
                        description=(
                            f"Line {i}: `{raw_type}` is used without a generic type parameter. "
                            "Raw types bypass compile-time type checking and may cause "
                            "`ClassCastException` at runtime."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=f"Use a parameterized type: `{raw_type}<String>` or `{raw_type}<MyType>`",
                        confidence=0.80,
                    )
                )
        return findings


class JavaResourceLeakRule(Rule):
    """JA003 — I/O resources opened without try-with-resources."""

    id = "JA003"
    name = "Resource leak — missing try-with-resources"
    severity = Severity.HIGH
    category = Category.QUALITY
    languages = [Language.JAVA]

    _RESOURCE = re.compile(
        r"\bnew\s+(FileInputStream|FileOutputStream|FileReader|FileWriter|"
        r"BufferedReader|BufferedWriter|InputStreamReader|OutputStreamWriter|"
        r"PrintWriter|Scanner|Connection|PreparedStatement|Statement|"
        r"ResultSet|Socket|ServerSocket|ZipFile|JarFile)\s*\("
    )
    _TRY_RESOURCE = re.compile(r"\btry\s*\(")

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
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            m = self._RESOURCE.search(line)
            if m:
                # Check surrounding 3 lines for try-with-resources
                window_start = max(0, i - 3)
                window = "\n".join(lines[window_start:i])
                if not self._TRY_RESOURCE.search(window):
                    resource = m.group(1)
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            title=f"`{resource}` opened without try-with-resources",
                            description=(
                                f"Line {i}: `{resource}` is instantiated outside a "
                                "try-with-resources block. If an exception occurs before `.close()`, "
                                "the resource leaks. CWE-404."
                            ),
                            line_start=i,
                            line_end=i,
                            suggestion=(
                                "Use try-with-resources: "
                                f"`try ({resource} r = new {resource}(...)) {{...}}`"
                            ),
                            confidence=0.82,
                        )
                    )
        return findings


class JavaBroadCatchRule(Rule):
    """JA004 — Catching Exception, RuntimeException, or Throwable is too broad."""

    id = "JA004"
    name = "Overly broad exception caught"
    severity = Severity.MEDIUM
    category = Category.QUALITY
    languages = [Language.JAVA]

    _pattern = re.compile(r"\bcatch\s*\(\s*(Exception|RuntimeException|Throwable)\s+\w+")

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
            m = self._pattern.search(line)
            if m:
                exc_type = m.group(1)
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title=f"Overly broad `catch ({exc_type})`",
                        description=(
                            f"Line {i}: Catching `{exc_type}` masks all exception types including "
                            "unexpected errors, making debugging difficult and hiding bugs."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Catch only the specific exceptions you expect and handle: "
                            "`catch (IOException | SQLException e)`"
                        ),
                        confidence=0.88,
                    )
                )
        return findings


class JavaSQLInjectionRule(Rule):
    """JA005 — SQL query built with string concatenation."""

    id = "JA005"
    name = "SQL injection via string concatenation"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = [Language.JAVA]

    _SQL_KEYWORDS = re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s")
    _CONCAT = re.compile(r'"\s*\+\s*\w+|\bString\.format\s*\(')

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
            if self._SQL_KEYWORDS.search(line) and self._CONCAT.search(line):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="SQL injection via string concatenation",
                        description=(
                            f"Line {i}: SQL query is built using string concatenation or "
                            "`String.format`. User-controlled input can alter the query structure. "
                            "CWE-89."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Use `PreparedStatement` with parameterized queries: "
                            '`PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); '
                            "ps.setInt(1, userId);`"
                        ),
                        confidence=0.87,
                    )
                )
        return findings


class JavaNullDereferenceRule(Rule):
    """JA006 — Method called on value that could be null (e.g. from Map.get())."""

    id = "JA006"
    name = "Potential NullPointerException"
    severity = Severity.HIGH
    category = Category.QUALITY
    languages = [Language.JAVA]

    # Patterns that return potentially null values
    _NULLABLE_SOURCES = re.compile(
        r"\b\w+\.(get|find|first|peek|poll|remove)\s*\([^)]*\)\."
        r"|\bOptional\.empty\b"
    )
    _DIRECT_ACCESS = re.compile(r"\b(get|find|first|peek|poll|remove)\s*\([^)]*\)\.\w+\s*\(")

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
            if self._NULLABLE_SOURCES.search(line) and ".get(" in line:
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="Potential NullPointerException — chained call on nullable",
                        description=(
                            f"Line {i}: Method chained directly on a value from `get()`/`find()` "
                            "which may return `null`. CWE-476."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Add a null check: `if (value != null) {{ value.method(); }}` "
                            "or use `Optional`: `Optional.ofNullable(map.get(key)).ifPresent(...)`"
                        ),
                        confidence=0.75,
                    )
                )
        return findings


ALL_RULES: list[Rule] = [
    JavaSystemOutRule(),
    JavaRawTypeRule(),
    JavaResourceLeakRule(),
    JavaBroadCatchRule(),
    JavaSQLInjectionRule(),
    JavaNullDereferenceRule(),
]
