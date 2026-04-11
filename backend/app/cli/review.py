#!/usr/bin/env python3
"""Odin CLI — review code locally before you push.

Usage:
    odin review <file>              # review a single file
    odin review <dir>               # review all supported files in a directory
    odin review --staged            # review git staged files
    odin review --diff HEAD~1       # review files changed since last commit

As a uvx one-liner:
    uvx odin review myfile.py --rules-only

As a git pre-push hook:
    bash install-hook.sh            # install into current repo
    git push --no-verify            # bypass when needed
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

# --------------------------------------------------------------------------- #
# Colour helpers (degrades gracefully without colorama)                        #
# --------------------------------------------------------------------------- #

try:
    from colorama import Fore, Style
    from colorama import init as _cinit

    _cinit()
    _RED = Fore.RED
    _YELLOW = Fore.YELLOW
    _GREEN = Fore.GREEN
    _BLUE = Fore.BLUE
    _CYAN = Fore.CYAN
    _RESET = Style.RESET_ALL
    _BOLD = "\033[1m"
    _DIM = "\033[2m"
except ImportError:
    _RED = _YELLOW = _GREEN = _BLUE = _CYAN = _RESET = _BOLD = _DIM = ""


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if code else text


def red(t: str) -> str:
    return _c(t, _RED)


def yellow(t: str) -> str:
    return _c(t, _YELLOW)


def green(t: str) -> str:
    return _c(t, _GREEN)


def blue(t: str) -> str:
    return _c(t, _BLUE)


def cyan(t: str) -> str:
    return _c(t, _CYAN)


def bold(t: str) -> str:
    return _c(t, _BOLD)


def dim(t: str) -> str:
    return _c(t, _DIM)


SEVERITY_COLOR = {
    "critical": red,
    "high": red,
    "medium": yellow,
    "low": blue,
    "info": dim,
}

SEVERITY_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# --------------------------------------------------------------------------- #
# Language mapping                                                             #
# --------------------------------------------------------------------------- #

EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
}

SKIP_DIRS = {
    "node_modules",
    "vendor",
    "__pycache__",
    ".git",
    "dist",
    "build",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
}

# Shebang patterns used when a file has no recognised extension
_SHEBANG_LANGUAGE: list[tuple[str, str]] = [
    ("python3", "python"),
    ("python", "python"),
    ("node", "javascript"),
    ("nodejs", "javascript"),
    ("bun", "javascript"),
    ("deno", "typescript"),
]


def _detect_language(path: Path) -> str | None:
    """Return a language string for *path*, trying extension then shebang."""
    lang = EXTENSION_TO_LANGUAGE.get(path.suffix.lower())
    if lang:
        return lang
    try:
        first_line = path.read_text(encoding="utf-8", errors="ignore").split("\n", 1)[0]
    except OSError:
        return None
    if not first_line.startswith("#!"):
        return None
    lower = first_line.lower()
    for token, detected in _SHEBANG_LANGUAGE:
        if token in lower:
            return detected
    return None


# --------------------------------------------------------------------------- #
# File collection                                                              #
# --------------------------------------------------------------------------- #


def collect_files(paths: list[str]) -> list[Path]:
    result: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_file():
            if _detect_language(path) is not None:
                result.append(path)
        elif path.is_dir():
            for f in sorted(path.rglob("*")):
                if not f.is_file():
                    continue
                if any(part in SKIP_DIRS for part in f.parts):
                    continue
                if _detect_language(f) is not None:
                    result.append(f)
    return result


def get_staged_files() -> list[Path]:
    try:
        out = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            text=True,
        ).strip()
        return collect_files(out.splitlines()) if out else []
    except subprocess.CalledProcessError:
        print(red("Error: not in a git repository"))
        sys.exit(1)


def get_diff_files(ref: str) -> list[Path]:
    try:
        out = subprocess.check_output(
            ["git", "diff", "--name-only", "--diff-filter=ACM", ref],
            text=True,
        ).strip()
        return collect_files(out.splitlines()) if out else []
    except subprocess.CalledProcessError:
        print(red(f"Error: could not diff against {ref}"))
        sys.exit(1)


# --------------------------------------------------------------------------- #
# Review runners                                                               #
# --------------------------------------------------------------------------- #


def run_rules_only(code: str, language_str: str) -> list[dict]:  # type: ignore[type-arg]
    """Deterministic rules — instant, no LLM required."""
    try:
        from app.models.enums import Language
        from app.rules.engine import rule_engine
        from app.rules.registry import register_all

        if not rule_engine.is_initialized():
            register_all()

        findings = rule_engine.check_all(code, Language(language_str))
        return [
            {
                "severity": f.severity.value,
                "category": f.category.value,
                "title": f.title,
                "description": f.description,
                "line_start": f.line_start,
                "suggestion": f.suggestion,
                "confidence": f.confidence,
                "source": "rule",
            }
            for f in findings
        ]
    except ImportError as exc:
        print(dim(f"  (rules engine unavailable: {exc})"))
        return []


def run_full_review(code: str, language_str: str, filename: str) -> list[dict]:  # type: ignore[type-arg]
    """Full AI + rules review (requires Odin backend running)."""
    api_url = os.environ.get("ODIN_API_URL", "http://localhost:8000")
    payload = json.dumps({"code": code, "language": language_str, "filename": filename}).encode()
    req = urllib.request.Request(
        f"{api_url}/api/review",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
            return [{**f, "source": "ai"} for f in data.get("findings", [])]
    except Exception as exc:
        print(yellow(f"  ⚠  Odin API unreachable ({exc}), running rules-only fallback"))
        return run_rules_only(code, language_str)


def run_local_review(code: str, language_str: str, filename: str) -> list[dict]:
    """Run full LangGraph pipeline in-process (no running server required)."""
    import asyncio

    try:
        from app.agents.graph import review_graph
        from app.models.enums import Language
        from app.models.state import ReviewState

        state: ReviewState = {
            "code": code,
            "language": language_str,
            "ast_summary": "",
            "metrics": None,
            "findings": [],
            "agent_outputs": [],
            "overall_score": 100,
            "summary": "",
            "codebase_context": "",
            "file_path": filename,
        }

        result = asyncio.get_event_loop().run_until_complete(
            review_graph.ainvoke(state, config={"callbacks": []})
        )

        return [
            {
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "category": f.category.value if hasattr(f.category, "value") else str(f.category),
                "title": f.title,
                "description": f.description,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "suggestion": f.suggestion,
                "fix_code": getattr(f, "fix_code", None),
                "confidence": f.confidence,
                "source": f.source or "ai",
            }
            for f in result.get("findings", [])
        ]
    except Exception as exc:
        print(yellow(f"  ⚠  Local review failed ({exc}), falling back to rules-only"))
        return run_rules_only(code, language_str)


# --------------------------------------------------------------------------- #
# Output                                                                       #
# --------------------------------------------------------------------------- #


def print_findings(findings: list[dict]) -> int:  # type: ignore[type-arg]
    """Print formatted findings. Returns count of critical+high."""
    blockers = 0
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.get("severity", "info"))):
        sev = f.get("severity", "info")
        icon = SEVERITY_ICON.get(sev, "•")
        col_fn = SEVERITY_COLOR.get(sev, lambda t: t)
        src = dim(f"[{f.get('source', '?')}]")
        line = f"  line {f['line_start']}" if f.get("line_start") else ""

        print(f"  {icon} {col_fn(sev.upper())} {src} {bold(f['title'])}{dim(line)}")
        desc = f.get("description", "")
        if desc:
            print(f"     {desc[:120]}")
        sug = f.get("suggestion", "")
        if sug:
            print(f"     {cyan('→')} {sug[:100]}")
        print()

        if sev in ("critical", "high"):
            blockers += 1
    return blockers


# --------------------------------------------------------------------------- #
# SARIF 2.1.0 output                                                          #
# --------------------------------------------------------------------------- #


def _to_sarif(all_findings: list[dict], files: list[Path]) -> dict:
    """Convert findings to SARIF 2.1.0 format."""
    rules = {}
    results = []

    for f in all_findings:
        rule_id = f.get("title", "unknown").replace(" ", "-").lower()[:50]
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f.get("title", "")},
                "fullDescription": {"text": f.get("description", "")},
                "defaultConfiguration": {
                    "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(f.get("severity", "info"), "note")
                },
            }

        result = {
            "ruleId": rule_id,
            "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(f.get("severity", "info"), "note"),
            "message": {"text": f.get("description", f.get("title", ""))},
        }

        if f.get("line_start"):
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("file", "unknown")},
                    "region": {"startLine": f["line_start"]},
                }
            }]
            if f.get("line_end"):
                result["locations"][0]["physicalLocation"]["region"]["endLine"] = f["line_end"]

        if f.get("fix_code"):
            result["fixes"] = [{
                "description": {"text": f.get("suggestion", "Apply fix")},
                "artifactChanges": [{
                    "artifactLocation": {"uri": f.get("file", "unknown")},
                    "replacements": [{
                        "deletedRegion": {"startLine": f.get("line_start", 1)},
                        "insertedContent": {"text": f["fix_code"]},
                    }],
                }],
            }]

        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "odin",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/RahulModugula/odin",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


# --------------------------------------------------------------------------- #
# Argument parser                                                              #
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="odin",
        description="Odin CLI — review code before you push",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Review a single file (rules-only, no server needed)
  odin review backend/app/main.py --rules-only

  # Review all Python files in a directory
  odin review backend/app

  # Review staged git changes (pre-push hook)
  odin review --staged

  # Rules-only mode (instant, zero LLM cost)
  odin review --staged --rules-only

  # Suppress output on clean scans (for CI/hooks)
  odin review --staged --quiet && git push

  # Output as JSON for CI/scripting
  odin review --staged --json | jq .

  # Filter by severity and confidence
  odin review backend/ --min-severity high --min-confidence 0.8

  # As a uvx one-liner (no install needed)
  uvx odin review myfile.py --rules-only
        """,
    )

    # Top-level subcommands — currently only "review"
    sub = parser.add_subparsers(dest="command")

    review = sub.add_parser(
        "review",
        help="Review files for code issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    review.add_argument("paths", nargs="*", help="Files or directories to review")
    review.add_argument("--staged", action="store_true", help="Review only git staged files")
    review.add_argument(
        "--diff",
        metavar="REF",
        help="Review files changed since REF (e.g. HEAD~1, origin/main)",
    )
    review.add_argument(
        "--rules-only",
        action="store_true",
        help="Run only deterministic rules (instant, zero LLM cost)",
    )
    review.add_argument(
        "--min-severity",
        default="low",
        choices=SEVERITY_ORDER,
        help="Show only findings at this severity or worse (default: low)",
    )
    review.add_argument(
        "--fail-on",
        default="high",
        choices=SEVERITY_ORDER + ["never"],
        help="Exit with code 1 if this severity or worse is found (default: high)",
    )
    review.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        metavar="FLOAT",
        help="Filter to findings with confidence >= FLOAT (0.0–1.0, default: 0.0)",
    )
    review.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON for CI/automation",
    )
    review.add_argument(
        "--sarif",
        action="store_true",
        help="Output findings as SARIF 2.1.0 (for GitHub Security tab)",
    )
    review.add_argument(
        "--local",
        action="store_true",
        help="Run full AI review locally (requires LLM API key, no server needed)",
    )
    review.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress banner and success messages (findings always shown)",
    )

    # ---- init subcommand ----
    init_parser = sub.add_parser("init", help="Set up Odin in the current repository")
    init_parser.add_argument("--hook", action="store_true", help="Also install git pre-push hook")

    return parser


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #


def _run_review(args: argparse.Namespace) -> None:
    """Execute the review sub-command."""
    if args.staged:
        files = get_staged_files()
        if not files:
            print(green("✓ No staged files to review"))
            return
    elif args.diff:
        files = get_diff_files(args.diff)
        if not files:
            print(green(f"✓ No changed files since {args.diff}"))
            return
    elif args.paths:
        files = collect_files(args.paths)
    else:
        files = collect_files(["."])

    if not files:
        print(yellow("No supported files found"))
        return

    min_idx = SEVERITY_ORDER.index(args.min_severity)
    fail_idx = SEVERITY_ORDER.index(args.fail_on) if args.fail_on != "never" else 99

    if not args.quiet:
        print(f"\n{bold('🔍 Odin Code Review')}\n")
        mode = "rules-only" if args.rules_only else "local (rules + AI)" if getattr(args, 'local', False) else "full (rules + AI)"
        print(f"{dim('Files:')} {len(files)}  {dim('Mode:')} {mode}\n")

    all_findings: list[dict] = []  # type: ignore[type-arg]

    for filepath in files:
        lang = _detect_language(filepath)
        if not lang:
            continue
        try:
            code = filepath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        print(bold(str(filepath)))

        if args.rules_only:
            findings = run_rules_only(code, lang)
        elif getattr(args, 'local', False):
            findings = run_local_review(code, lang, str(filepath))
        else:
            findings = run_full_review(code, lang, str(filepath))

        for f in findings:
            f["file"] = str(filepath)

        findings = [
            f for f in findings if SEVERITY_ORDER.index(f.get("severity", "info")) <= min_idx
        ]
        if args.min_confidence > 0:
            findings = [f for f in findings if f.get("confidence", 1.0) >= args.min_confidence]

        if not findings:
            if not args.quiet:
                print(f"  {green('✓ No issues found')}\n")
        else:
            if not args.quiet:
                print_findings(findings)
            else:
                print(bold(str(filepath)))
                print_findings(findings)
            all_findings.extend(findings)

    # ---- SARIF output (early return) ----
    if args.sarif:
        sarif = _to_sarif(all_findings, files)
        print(json.dumps(sarif, indent=2))
        return

    # ---- summary ----
    if all_findings:
        counts: dict[str, int] = {}
        for f in all_findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1

        print(bold(f"Summary: {len(all_findings)} finding(s) in {len(files)} file(s)"))
        for sev in SEVERITY_ORDER:
            if counts.get(sev):
                col = SEVERITY_COLOR.get(sev, lambda t: t)
                print(f"  {col(sev)}: {counts[sev]}")

        if args.json:
            print("\n" + json.dumps(all_findings, indent=2))
    else:
        if not args.quiet:
            print(green("✓ All clear!"))

    # ---- exit code ----
    if args.fail_on != "never":
        blockers = [
            f for f in all_findings if SEVERITY_ORDER.index(f.get("severity", "info")) <= fail_idx
        ]
        if blockers:
            print(f"\n{red(f'✗ {len(blockers)} blocking finding(s) at {args.fail_on}+ severity')}")
            sys.exit(1)


def main() -> None:
    """Entry point for `odin` CLI (uvx odin / pip install odin)."""
    parser = _build_parser()

    # Support legacy invocation: `odin review file.py` is the canonical form.
    # If the user calls the script directly without a sub-command we show help.
    args = parser.parse_args()

    if args.command == "review":
        _run_review(args)
    elif args.command == "init":
        from app.cli.init import run_init

        run_init(args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
