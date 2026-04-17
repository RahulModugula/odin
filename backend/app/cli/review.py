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
from typing import Any

# --------------------------------------------------------------------------- #
# Colour helpers (degrades gracefully without colorama)                        #
# --------------------------------------------------------------------------- #

try:
    from colorama import Fore, Style  # type: ignore[import-untyped]
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


def _identity(t: str) -> str:
    return t


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


def run_local_review(code: str, language_str: str, filename: str) -> list[dict[str, Any]]:
    """Run full LangGraph pipeline in-process (no running server required)."""
    import asyncio

    try:
        from app.agents.graph import review_graph
        from app.models.state import ReviewState

        state: ReviewState = {
            "code": code,
            "language": language_str,
            "ast_summary": "",
            "metrics": None,  # type: ignore[typeddict-item]
            "findings": [],
            "agent_outputs": [],
            "overall_score": 100,
            "summary": "",
            "codebase_context": "",
            "file_path": filename,
        }

        result = asyncio.get_event_loop().run_until_complete(
            review_graph.ainvoke(state, config={"callbacks": []})  # type: ignore[call-overload]
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
        col_fn = SEVERITY_COLOR.get(sev, _identity)
        src = dim(f"[{f.get('source', '?')}]")
        line = f"  line {f['line_start']}" if f.get("line_start") else ""
        confidence = f.get("confidence")
        conf_str = f" ({int(confidence * 100)}%)" if confidence else ""

        print(f"  {icon} {col_fn(sev.upper())} {src} {bold(f['title'])}{dim(line)}{dim(conf_str)}")
        desc = f.get("description", "")
        if desc:
            for dline in desc.split("\n")[:3]:
                print(f"     {dim(dline[:120])}")
        sug = f.get("suggestion", "")
        if sug:
            print(f"     {cyan('→')} {sug[:100]}")
        fix = f.get("fix_code")
        if fix:
            print(f"     {green('Fix:')}")
            for fix_line in fix.split("\n")[:5]:
                print(f"       {green('+')} {fix_line}")
            if fix.count("\n") > 5:
                print(f"       {dim('...')}")
        print()

        if sev in ("critical", "high"):
            blockers += 1
    return blockers


# --------------------------------------------------------------------------- #
# SARIF 2.1.0 output                                                          #
# --------------------------------------------------------------------------- #


def _to_sarif(all_findings: list[dict[str, Any]], files: list[Path]) -> dict[str, Any]:
    """Convert findings to SARIF 2.1.0 format."""
    rules = {}
    results = []

    for f in all_findings:
        rule_id = f.get("title", "unknown").replace(" ", "-").lower()[:50]
        _sev_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f.get("title", "")},
                "fullDescription": {"text": f.get("description", "")},
                "defaultConfiguration": {"level": _sev_map.get(f.get("severity", "info"), "note")},
            }

        result = {
            "ruleId": rule_id,
            "level": _sev_map.get(f.get("severity", "info"), "note"),
            "message": {"text": f.get("description", f.get("title", ""))},
        }

        if f.get("line_start"):
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("file", "unknown")},
                        "region": {"startLine": f["line_start"]},
                    }
                }
            ]
            if f.get("line_end"):
                result["locations"][0]["physicalLocation"]["region"]["endLine"] = f["line_end"]

        if f.get("fix_code"):
            result["fixes"] = [
                {
                    "description": {"text": f.get("suggestion", "Apply fix")},
                    "artifactChanges": [
                        {
                            "artifactLocation": {"uri": f.get("file", "unknown")},
                            "replacements": [
                                {
                                    "deletedRegion": {"startLine": f.get("line_start", 1)},
                                    "insertedContent": {"text": f["fix_code"]},
                                }
                            ],
                        }
                    ],
                }
            ]

        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "odin",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/RahulModugula/odin",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


# --------------------------------------------------------------------------- #
# Fix application                                                              #
# --------------------------------------------------------------------------- #


def _show_diff(filepath: Path, line_start: int, line_end: int, fix_code: str) -> None:
    """Print a minimal before/after diff for one fix."""
    try:
        lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines()
        old = lines[line_start - 1 : line_end]
        print(f"  {dim(f'lines {line_start}–{line_end}')}")
        for ln in old:
            print(f"  {red('- ' + ln)}")
        for ln in fix_code.splitlines():
            print(f"  {green('+ ' + ln)}")
    except Exception:
        print(f"  {dim('(could not read current file content)')}")


def _apply_fix(filepath: Path, line_start: int, line_end: int, fix_code: str) -> bool:
    """Replace lines line_start..line_end (1-indexed, inclusive) with fix_code."""
    try:
        text = filepath.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        replacement = [fix_code + "\n"] if not fix_code.endswith("\n") else [fix_code]
        new_lines = lines[: line_start - 1] + replacement + lines[line_end:]
        filepath.write_text("".join(new_lines), encoding="utf-8")
        return True
    except Exception as exc:
        print(red(f"  Error applying fix: {exc}"))
        return False


def _run_fix(args: argparse.Namespace) -> None:
    """Execute the fix sub-command — apply LLM-suggested fixes interactively."""
    # Collect fixable findings from JSON file or fresh review
    fixable: list[dict[str, Any]] = []

    if getattr(args, "from_json", None):
        try:
            raw = Path(args.from_json).read_text(encoding="utf-8")
            data = json.loads(raw)
            # Accept both a list of findings and a review-result envelope
            if isinstance(data, list):
                fixable = data
            elif isinstance(data, dict):
                fixable = data.get("findings", [])
        except Exception as exc:
            print(red(f"Could not load findings from {args.from_json}: {exc}"))
            sys.exit(1)
    else:
        if not args.fix_paths:
            print(yellow("Specify file paths or --from-json <findings.json>"))
            sys.exit(1)
        files = collect_files(args.fix_paths)
        for filepath in files:
            lang = _detect_language(filepath)
            if not lang:
                continue
            try:
                code = filepath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            results = run_rules_only(code, lang)
            for f in results:
                f["file"] = str(filepath)
            fixable.extend(results)

    # Filter to findings that actually have a fix
    fixable = [f for f in fixable if f.get("fix_code") and f.get("line_start")]

    if not fixable:
        print(green("✓ No fixable findings found."))
        return

    print(f"\n{bold('🔧 Odin Fix')}")
    print(f"{dim(f'{len(fixable)} fixable finding(s) found')}\n")

    # Group by file, sort each group bottom-to-top so line offsets stay valid
    by_file: dict[str, list[dict[str, Any]]] = {}
    for f in fixable:
        by_file.setdefault(f.get("file", "unknown"), []).append(f)

    applied = skipped = 0

    for filepath_str, file_findings in by_file.items():
        filepath = Path(filepath_str)
        # Apply bottom-to-top: higher line numbers first so earlier offsets stay valid
        sorted_findings = sorted(file_findings, key=lambda f: f.get("line_start", 0), reverse=True)
        print(bold(filepath_str))

        for finding in sorted_findings:
            sev = finding.get("severity", "info")
            icon = SEVERITY_ICON.get(sev, "•")
            col_fn = SEVERITY_COLOR.get(sev, _identity)
            print(f"  {icon} {col_fn(sev.upper())} {bold(finding['title'])}")

            line_start = int(finding["line_start"])
            line_end = int(finding.get("line_end") or line_start)
            fix_code = finding["fix_code"]

            _show_diff(filepath, line_start, line_end, fix_code)

            if getattr(args, "auto", False):
                ok = _apply_fix(filepath, line_start, line_end, fix_code)
                if ok:
                    print(f"  {green('✓ Applied')}\n")
                    applied += 1
                else:
                    skipped += 1
            else:
                try:
                    answer = input("  Apply this fix? [y/N] ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                if answer in ("y", "yes"):
                    ok = _apply_fix(filepath, line_start, line_end, fix_code)
                    if ok:
                        print(f"  {green('✓ Applied')}\n")
                        applied += 1
                    else:
                        skipped += 1
                else:
                    print(f"  {dim('Skipped')}\n")
                    skipped += 1

    print(bold(f"\nDone: {applied} fix(es) applied, {skipped} skipped."))


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

  # Review staged git changes (pre-push hook)
  odin review --staged

  # Apply AI-suggested fixes interactively
  odin fix backend/app/main.py --rules-only

  # Apply all fixes automatically (CI)
  odin fix --from-json findings.json --auto

  # Quality gate: fail CI if score < 70 or any critical findings
  odin review --staged --fail-on-score 70 --fail-on critical

  # Load per-project settings from .odin.yml automatically
  odin review backend/
        """,
    )

    # Top-level subcommands
    sub = parser.add_subparsers(dest="command")

    # ---- review subcommand ----
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
        default=None,
        choices=SEVERITY_ORDER,
        help="Show only findings at this severity or worse (default: low, or from .odin.yml)",
    )
    review.add_argument(
        "--fail-on",
        default=None,
        choices=SEVERITY_ORDER + ["never"],
        help="Exit code 1 if this severity or worse found (default: high, or from .odin.yml)",
    )
    review.add_argument(
        "--fail-on-score",
        type=int,
        default=None,
        metavar="N",
        help="Exit with code 2 if overall review score < N (0–100)",
    )
    review.add_argument(
        "--min-confidence",
        type=float,
        default=None,
        metavar="FLOAT",
        help="Filter to findings with confidence >= FLOAT (0.0–1.0)",
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
    review.add_argument(
        "--no-config",
        action="store_true",
        help="Ignore .odin.yml project config",
    )

    # ---- fix subcommand ----
    fix_p = sub.add_parser(
        "fix",
        help="Apply AI-suggested fixes to findings interactively",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Apply fix_code suggestions from Odin findings.\n\n"
            "Runs a rules-only review on the given files, shows each proposed fix\n"
            "with a before/after diff, and applies fixes you confirm.\n\n"
            "Examples:\n"
            "  odin fix backend/app/main.py           # interactive review + fix\n"
            "  odin fix --from-json findings.json     # fix from saved JSON output\n"
            "  odin fix --staged --auto               # auto-apply all fixes (CI)\n"
        ),
    )
    fix_p.add_argument("fix_paths", nargs="*", help="Files or directories to review and fix")
    fix_p.add_argument("--staged", action="store_true", help="Fix staged files")
    fix_p.add_argument(
        "--from-json",
        metavar="FILE",
        help="Load findings from a JSON file (output of odin review --json)",
    )
    fix_p.add_argument(
        "--auto",
        action="store_true",
        help="Apply all fixes without confirmation (use in CI after review)",
    )

    # ---- init subcommand ----
    init_parser = sub.add_parser("init", help="Set up Odin in the current repository")
    init_parser.add_argument("--hook", action="store_true", help="Also install git pre-push hook")

    return parser


# --------------------------------------------------------------------------- #
# Main review runner                                                           #
# --------------------------------------------------------------------------- #


def _run_review(args: argparse.Namespace) -> None:
    """Execute the review sub-command."""
    # Load per-project config (.odin.yml) unless --no-config was passed
    from app.cli.config import load_config

    cfg = load_config() if not getattr(args, "no_config", False) else None

    # Resolve effective settings: CLI flag > config > default
    min_severity: str = args.min_severity or (cfg.min_severity if cfg else None) or "low"
    fail_on: str = args.fail_on or (cfg.fail_on if cfg else None) or "high"
    min_confidence: float = (
        args.min_confidence
        if args.min_confidence is not None
        else (cfg.min_confidence if cfg else 0.0)
    )

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

    # Apply .odin.yml exclude patterns
    if cfg and cfg.exclude:
        files = [f for f in files if not cfg.is_excluded(str(f))]

    if not files:
        print(yellow("No supported files found"))
        return

    min_idx = SEVERITY_ORDER.index(min_severity)
    fail_idx = SEVERITY_ORDER.index(fail_on) if fail_on != "never" else 99

    if not args.quiet:
        print(f"\n{bold('🔍 Odin Code Review')}\n")
        if getattr(args, "rules_only", False):
            mode = "rules-only"
        elif getattr(args, "local", False):
            mode = "local (rules + AI)"
        else:
            mode = "full (rules + AI)"
        if cfg and cfg.config_path:
            print(f"{dim('Config:')} {cfg.config_path}")
        print(f"{dim('Files:')} {len(files)}  {dim('Mode:')} {mode}\n")

    all_findings: list[dict[str, Any]] = []
    # Track per-file scores for quality gate
    file_scores: list[int] = []

    for filepath in files:
        lang = _detect_language(filepath)
        if not lang:
            continue
        try:
            code = filepath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        if not args.quiet:
            print(bold(str(filepath)))

        if getattr(args, "rules_only", False):
            findings = run_rules_only(code, lang)
        elif getattr(args, "local", False):
            findings = run_local_review(code, lang, str(filepath))
        else:
            findings = run_full_review(code, lang, str(filepath))

        for f in findings:
            f["file"] = str(filepath)

        # Apply .odin.yml ignore rules
        if cfg and cfg.ignore:
            findings = [
                f for f in findings if not cfg.is_ignored(f.get("title", ""), str(filepath))
            ]

        findings = [
            f for f in findings if SEVERITY_ORDER.index(f.get("severity", "info")) <= min_idx
        ]
        if min_confidence > 0:
            findings = [f for f in findings if f.get("confidence", 1.0) >= min_confidence]

        if not findings:
            if not args.quiet:
                print(f"  {green('✓ No issues found')}\n")
        else:
            print_findings(findings)
            all_findings.extend(findings)

        # Collect score for quality gate (only available from full/local review)
        if isinstance(findings, list) and any(f.get("overall_score") is not None for f in findings):
            scores = [f["overall_score"] for f in findings if f.get("overall_score") is not None]
            if scores:
                file_scores.append(min(scores))

    # ---- SARIF output (early return) ----
    if args.sarif:
        sarif = _to_sarif(all_findings, files)
        print(json.dumps(sarif, indent=2))
        return

    # ---- summary ----
    if all_findings:
        counts: dict[str, int] = {}
        sources: dict[str, int] = {}
        for f in all_findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
            src = f.get("source", "unknown")
            sources[src] = sources.get(src, 0) + 1

        if not args.quiet:
            print(bold(f"\n{'─' * 50}"))
            print(bold(f"Summary: {len(all_findings)} finding(s) in {len(files)} file(s)"))
            print(f"{dim('─' * 50)}")
            for sev in SEVERITY_ORDER:
                if counts.get(sev):
                    col = SEVERITY_COLOR.get(sev, _identity)
                    bar = "█" * counts[sev]
                    print(f"  {col(f'{sev:>8}')}: {counts[sev]:>2}  {dim(bar)}")
            if sources:
                print(f"{dim('─' * 50)}")
                src_parts = [f"{dim(k)}: {v}" for k, v in sorted(sources.items())]
                print(f"  By source: {', '.join(src_parts)}")
            print(f"{dim('─' * 50)}")

        if args.json:
            print("\n" + json.dumps(all_findings, indent=2))
    else:
        if not args.quiet:
            print(green("✓ All clear!"))

    # ---- exit code 1: blocking findings ----
    if fail_on != "never":
        blockers = [
            f for f in all_findings if SEVERITY_ORDER.index(f.get("severity", "info")) <= fail_idx
        ]
        if blockers:
            print(f"\n{red(f'✗ {len(blockers)} blocking finding(s) at {fail_on}+ severity')}")
            sys.exit(1)

    # ---- exit code 2: quality gate ----
    gate_score: int | None = args.fail_on_score
    gate_max_critical: int = -1
    gate_max_high: int = -1

    if cfg and cfg.quality_gate.is_active():
        gate_score = gate_score or cfg.quality_gate.min_score or None
        gate_max_critical = cfg.quality_gate.max_critical
        gate_max_high = cfg.quality_gate.max_high

    gate_failures: list[str] = []

    if gate_score and file_scores and min(file_scores) < gate_score:
        gate_failures.append(f"score {min(file_scores)} < required {gate_score}")

    critical_count = sum(1 for f in all_findings if f.get("severity") == "critical")
    high_count = sum(1 for f in all_findings if f.get("severity") == "high")

    if gate_max_critical >= 0 and critical_count > gate_max_critical:
        gate_failures.append(f"{critical_count} critical (max {gate_max_critical})")
    if gate_max_high >= 0 and high_count > gate_max_high:
        gate_failures.append(f"{high_count} high (max {gate_max_high})")

    if gate_failures:
        print(f"\n{red('✗ Quality gate failed:')} {', '.join(gate_failures)}")
        sys.exit(2)


def main() -> None:
    """Entry point for `odin` CLI (uvx odin / pip install odin)."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "review":
        _run_review(args)
    elif args.command == "fix":
        if getattr(args, "staged", False):
            args.fix_paths = [str(p) for p in get_staged_files()]
        _run_fix(args)
    elif args.command == "init":
        from app.cli.init import run_init

        run_init(args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
