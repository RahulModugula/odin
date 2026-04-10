"""Go-specific deterministic rules."""

from __future__ import annotations

import re

from app.models.enums import Category, Language, Severity
from app.models.schemas import Finding
from app.rules.engine import Rule


class GoErrorIgnoredRule(Rule):
    """GO001 — Ignoring error return values is the most common Go bug."""

    id = "GO001"
    name = "Error return value ignored"
    severity = Severity.HIGH
    category = Category.QUALITY
    languages = [Language.GO]

    # Multi-return call where result is assigned to _ or completely discarded
    _BLANK_ERR = re.compile(r"\b(\w+(?:,\s*\w+)*),\s*_\s*:?=")
    # Common functions that return errors that must be checked
    _MUST_CHECK = re.compile(
        r"\b(os\.(Open|Create|Remove|Rename|Mkdir|MkdirAll|Stat|Chmod|Chown)|"
        r"io\.Copy|io\.ReadAll|io\.WriteString|"
        r"json\.(Unmarshal|Marshal|Decode|Encode)|"
        r"http\.(Get|Post|PostForm|NewRequest)|"
        r"db\.(Query|Exec|QueryRow|Begin|Prepare)|"
        r"rows\.(Scan|Next|Err)|"
        r"tx\.(Commit|Rollback)|"
        r"fmt\.(Fprintf|Fprintln|Fprint))\s*\("
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

            # Pattern: result, _ := criticalFunc(...)
            if self._BLANK_ERR.search(line) and self._MUST_CHECK.search(line):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="Error return value discarded with `_`",
                        description=(
                            f"Line {i}: The error returned by a critical function is silently "
                            "discarded using `_`. Unhandled errors cause silent failures and "
                            "data corruption. CWE-391."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Assign the error to a variable and check it: "
                            "`result, err := f(); if err != nil { return err }`"
                        ),
                        confidence=0.88,
                    )
                )
        return findings


class GoPanicInLibraryRule(Rule):
    """GO002 — panic() in a library function propagates up and kills the caller."""

    id = "GO002"
    name = "panic() in non-main code"
    severity = Severity.HIGH
    category = Category.QUALITY
    languages = [Language.GO]

    _PANIC = re.compile(r"\bpanic\s*\(")
    _IN_MAIN = re.compile(r"^func\s+main\s*\(\s*\)", re.MULTILINE)

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        # If the file has func main(), panic is more acceptable
        is_main_package = "package main" in code and self._IN_MAIN.search(code) is not None

        for i, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if self._PANIC.search(line):
                if is_main_package:
                    continue  # panic in main is acceptable
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="`panic()` used in library code",
                        description=(
                            f"Line {i}: `panic()` in library/package code unwinds the entire "
                            "call stack and kills the goroutine. Callers cannot recover gracefully."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Return an `error` instead of panicking: "
                            '`return nil, fmt.Errorf("invalid input: %w", err)`'
                        ),
                        confidence=0.82,
                    )
                )
        return findings


class GoGoroutineLeakRule(Rule):
    """GO003 — goroutine launched without any synchronization mechanism."""

    id = "GO003"
    name = "Potential goroutine leak"
    severity = Severity.MEDIUM
    category = Category.QUALITY
    languages = [Language.GO]

    _GO_FUNC = re.compile(r"\bgo\s+func\s*\(")
    _SYNC = re.compile(
        r"\bwg\.(Add|Done|Wait)\b|"
        r"\bsync\.WaitGroup\b|"
        r"<-\s*(ctx\.Done|done|quit|stop|cancel)|"
        r"\bcontext\.WithCancel\b|"
        r"errgroup\."
    )

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        has_sync = bool(self._SYNC.search(code))

        for i, line in enumerate(code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if self._GO_FUNC.search(line) and not has_sync:
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="Goroutine launched without synchronization",
                        description=(
                            f"Line {i}: Anonymous goroutine started with no `sync.WaitGroup`, "
                            "`context.WithCancel`, or channel-based stop signal. The goroutine "
                            "may outlive its parent and leak."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Use `sync.WaitGroup`, `errgroup.Group`, or pass a `context.Context` "
                            "so the goroutine can be stopped and its completion awaited."
                        ),
                        confidence=0.75,
                    )
                )
        return findings


class GoSQLInjectionRule(Rule):
    """GO004 — fmt.Sprintf used to build SQL strings."""

    id = "GO004"
    name = "SQL injection via string formatting"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = [Language.GO]

    _SQL_KEYWORDS = re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s")
    _FMT_INTERP = re.compile(r"fmt\.(Sprintf|Fprintf)\s*\(|string\s*\+|%[sdvf]")

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
            if self._SQL_KEYWORDS.search(line) and self._FMT_INTERP.search(line):
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="SQL injection via string formatting",
                        description=(
                            f"Line {i}: SQL query built with `fmt.Sprintf` or string concatenation "
                            "allows SQL injection if any part is user-controlled. CWE-89."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Use parameterized queries: "
                            '`db.QueryContext(ctx, "SELECT * FROM users WHERE id = $1", id)`'
                        ),
                        confidence=0.85,
                    )
                )
        return findings


class GoMutexUnlockRule(Rule):
    """GO005 — Mutex locked but Unlock not deferred (risk of deadlock on panic)."""

    id = "GO005"
    name = "Mutex Lock without deferred Unlock"
    severity = Severity.MEDIUM
    category = Category.QUALITY
    languages = [Language.GO]

    _LOCK = re.compile(r"\b\w+\.(Lock|RLock)\s*\(\s*\)")
    _DEFER_UNLOCK = re.compile(r"\bdefer\s+[\w.]+\.(Unlock|RUnlock)\s*\(\s*\)")

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
            if stripped.startswith("//"):
                continue
            if self._LOCK.search(line):
                # Check next 3 lines for a defer unlock
                window = "\n".join(lines[i : min(i + 3, len(lines))])
                if not self._DEFER_UNLOCK.search(window):
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            title="Mutex.Lock() without `defer Unlock()`",
                            description=(
                                f"Line {i}: Mutex locked but Unlock is not deferred. "
                                "If a panic occurs before Unlock(), the mutex deadlocks permanently."
                            ),
                            line_start=i,
                            line_end=i,
                            suggestion=(
                                "Immediately follow Lock() with `defer mu.Unlock()` to ensure "
                                "the mutex is always released."
                            ),
                            confidence=0.80,
                        )
                    )
        return findings


class GoContextFirstArgRule(Rule):
    """GO006 — Functions accepting context should have it as the first parameter."""

    id = "GO006"
    name = "context.Context not first parameter"
    severity = Severity.LOW
    category = Category.QUALITY
    languages = [Language.GO]

    # func with context.Context somewhere but not as first param
    _FUNC_SIG = re.compile(r"^func\s+\w+\s*\(([^)]+)\)")
    _CTX_PARAM = re.compile(r"context\.Context")

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
            m = self._FUNC_SIG.match(stripped)
            if not m:
                continue
            params = m.group(1)
            if not self._CTX_PARAM.search(params):
                continue
            # Split params and check if context is first
            param_list = [p.strip() for p in params.split(",")]
            if param_list and "context.Context" not in param_list[0]:
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title="`context.Context` is not the first parameter",
                        description=(
                            f"Line {i}: By Go convention, `context.Context` should always be "
                            "the first parameter, named `ctx`. This is enforced by `go vet` "
                            "and expected by the standard library."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Move `context.Context` to be the first parameter: "
                            "`func Foo(ctx context.Context, ...)`"
                        ),
                        confidence=0.85,
                    )
                )
        return findings


class GoHardcodedIPRule(Rule):
    """GO007 — Hardcoded IP addresses make code non-portable."""

    id = "GO007"
    name = "Hardcoded IP address"
    severity = Severity.LOW
    category = Category.MAINTAINABILITY
    languages = [Language.GO]

    _IP_PATTERN = re.compile(r'["\'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})["\']')
    _ALLOWED = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}

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
            m = self._IP_PATTERN.search(line)
            if m and m.group(1) not in self._ALLOWED:
                findings.append(
                    Finding(
                        severity=self.severity,
                        category=self.category,
                        title=f"Hardcoded IP address: {m.group(1)}",
                        description=(
                            f"Line {i}: IP address `{m.group(1)}` is hardcoded. "
                            "This makes the service non-portable across environments."
                        ),
                        line_start=i,
                        line_end=i,
                        suggestion=(
                            "Load the address from config or environment variable: "
                            '`os.Getenv("SERVICE_HOST")`'
                        ),
                        confidence=0.8,
                    )
                )
        return findings


class GoUnbufferedChannelSendRule(Rule):
    """GO008 — Sending to an unbuffered channel without a goroutine can deadlock."""

    id = "GO008"
    name = "Unbuffered channel send may deadlock"
    severity = Severity.MEDIUM
    category = Category.QUALITY
    languages = [Language.GO]

    # make(chan T) without a size argument
    _UNBUFFERED_MAKE = re.compile(r"\bmake\s*\(\s*chan\s+\w[\w.*\[\]]*\s*\)")
    # Channel send: ch <- value on same channel
    _CHAN_SEND = re.compile(r"\b\w+\s*<-\s*\w")
    # Inside a goroutine
    _GOROUTINE = re.compile(r"\bgo\s+func\b|\bgo\s+\w+\s*\(")

    def check(
        self,
        code: str,
        language: Language,
        tree: object = None,
        structure: object = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        lines = code.splitlines()
        has_goroutine = bool(self._GOROUTINE.search(code))

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            # Flag: unbuffered channel created, send happens in same scope, no goroutine
            if self._UNBUFFERED_MAKE.search(line):
                # Look ahead 20 lines for a send without a concurrent goroutine
                window_end = min(len(lines), i + 20)
                window = "\n".join(lines[i : window_end])
                if self._CHAN_SEND.search(window) and not has_goroutine:
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            title="Unbuffered channel send without concurrent receiver",
                            description=(
                                f"Line {i}: `make(chan ...)` creates an unbuffered channel. "
                                "Sending to it blocks until a receiver is ready. If no goroutine "
                                "is launched to receive, this will deadlock."
                            ),
                            line_start=i,
                            line_end=i,
                            suggestion=(
                                "Either use a buffered channel `make(chan T, n)`, launch a goroutine "
                                "to receive, or use `select` with a `default` case to avoid blocking."
                            ),
                            confidence=0.72,
                        )
                    )
        return findings


ALL_RULES: list[Rule] = [
    GoErrorIgnoredRule(),
    GoPanicInLibraryRule(),
    GoGoroutineLeakRule(),
    GoSQLInjectionRule(),
    GoMutexUnlockRule(),
    GoContextFirstArgRule(),
    GoHardcodedIPRule(),
    GoUnbufferedChannelSendRule(),
]
