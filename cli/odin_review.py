#!/usr/bin/env python3
"""Odin CLI — review code locally before you push.

Usage:
    python odin_review.py <file>          # review a single file
    python odin_review.py <dir>           # review all supported files in a directory
    python odin_review.py --staged        # review git staged files
    python odin_review.py --diff HEAD~1   # review files changed since last commit

As a git pre-push hook:
    bash install-hook.sh                  # install into current repo
    git push --no-verify                  # bypass when needed
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
    from colorama import Fore, Style, init as _cinit
    _cinit()
    _RED    = Fore.RED
    _YELLOW = Fore.YELLOW
    _GREEN  = Fore.GREEN
    _BLUE   = Fore.BLUE
    _CYAN   = Fore.CYAN
    _RESET  = Style.RESET_ALL
    _BOLD   = "\033[1m"
    _DIM    = "\033[2m"
except ImportError:
    _RED = _YELLOW = _GREEN = _BLUE = _CYAN = _RESET = _BOLD = _DIM = ""


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if code else text


def red(t: str) -> str:    return _c(t, _RED)
def yellow(t: str) -> str: return _c(t, _YELLOW)
def green(t: str) -> str:  return _c(t, _GREEN)
def blue(t: str) -> str:   return _c(t, _BLUE)
def cyan(t: str) -> str:   return _c(t, _CYAN)
def bold(t: str) -> str:   return _c(t, _BOLD)
def dim(t: str) -> str:    return _c(t, _DIM)


SEVERITY_COLOR = {
    "critical": red,
    "high":     red,
    "medium":   yellow,
    "low":      blue,
    "info":     dim,
}

SEVERITY_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# --------------------------------------------------------------------------- #
# Paths and language mapping                                                   #
# --------------------------------------------------------------------------- #

_SCRIPT_DIR  = Path(__file__).resolve().parent
_BACKEND_DIR = _SCRIPT_DIR.parent / "backend"
if (_BACKEND_DIR / "app").exists():
    sys.path.insert(0, str(_BACKEND_DIR))

EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py":   "python",
    ".js":   "javascript",
    ".jsx":  "javascript",
    ".ts":   "typescript",
    ".tsx":  "typescript",
    ".go":   "go",
    ".rs":   "rust",
    ".java": "java",
}

SKIP_DIRS = {"node_modules", "vendor", "__pycache__", ".git", "dist", "build",
             ".venv", "venv", ".tox", ".mypy_cache"}


# --------------------------------------------------------------------------- #
# File collection                                                              #
# --------------------------------------------------------------------------- #

def collect_files(paths: list[str]) -> list[Path]:
    result: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_file():
            if path.suffix.lower() in EXTENSION_TO_LANGUAGE:
                result.append(path)
        elif path.is_dir():
            for f in sorted(path.rglob("*")):
                if not f.is_file():
                    continue
                if f.suffix.lower() not in EXTENSION_TO_LANGUAGE:
                    continue
                if any(part in SKIP_DIRS for part in f.parts):
                    continue
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

def run_rules_only(code: str, language_str: str) -> list[dict]:
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
                "severity":   f.severity.value,
                "category":   f.category.value,
                "title":      f.title,
                "description": f.description,
                "line_start": f.line_start,
                "suggestion": f.suggestion,
                "confidence": f.confidence,
                "source":     "rule",
            }
            for f in findings
        ]
    except ImportError as exc:
        print(dim(f"  (rules engine unavailable: {exc})"))
        return []


def run_full_review(code: str, language_str: str, filename: str) -> list[dict]:
    """Full AI + rules review (requires Odin backend running)."""
    api_url = os.environ.get("ODIN_API_URL", "http://localhost:8000")
    payload  = json.dumps({"code": code, "language": language_str, "filename": filename}).encode()
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


# --------------------------------------------------------------------------- #
# Output                                                                       #
# --------------------------------------------------------------------------- #

def print_findings(findings: list[dict]) -> int:
    """Print formatted findings. Returns count of critical+high."""
    blockers = 0
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.get("severity", "info"))):
        sev     = f.get("severity", "info")
        icon    = SEVERITY_ICON.get(sev, "•")
        col_fn  = SEVERITY_COLOR.get(sev, lambda t: t)
        src     = dim(f"[{f.get('source', '?')}]")
        line    = f"  line {f['line_start']}" if f.get("line_start") else ""

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
# Main                                                                         #
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Odin CLI — review code before you push",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("paths", nargs="*", help="Files or directories to review")
    parser.add_argument("--staged",    action="store_true", help="Review git staged files")
    parser.add_argument("--diff",      metavar="REF",       help="Review files changed since REF (e.g. HEAD~1)")
    parser.add_argument("--rules-only",action="store_true", help="Deterministic rules only — instant, no LLM")
    parser.add_argument("--min-severity", default="low",
                        choices=SEVERITY_ORDER, help="Minimum severity to show (default: low)")
    parser.add_argument("--fail-on", default="high",
                        choices=SEVERITY_ORDER + ["never"],
                        help="Exit 1 if this severity is found (default: high)")
    parser.add_argument("--min-confidence", type=float, default=0.0, metavar="FLOAT",
                        help="Only show findings with confidence >= this value (0.0–1.0)")
    parser.add_argument("--json", action="store_true", help="Output JSON")

    args = parser.parse_args()

    # ---- collect files ----
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

    min_idx  = SEVERITY_ORDER.index(args.min_severity)
    fail_idx = SEVERITY_ORDER.index(args.fail_on) if args.fail_on != "never" else 99

    print(f"\n{bold('🔍 Odin Code Review')}\n")
    print(f"{dim('Files:')} {len(files)}  {dim('Mode:')} {'rules-only' if args.rules_only else 'full (rules + AI)'}\n")

    all_findings: list[dict] = []

    for filepath in files:
        lang = EXTENSION_TO_LANGUAGE.get(filepath.suffix.lower())
        if not lang:
            continue
        try:
            code = filepath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        print(bold(str(filepath)))

        if args.rules_only:
            findings = run_rules_only(code, lang)
        else:
            findings = run_full_review(code, lang, str(filepath))
        findings = [f for f in findings if SEVERITY_ORDER.index(f.get("severity", "info")) <= min_idx]
        if args.min_confidence > 0:
            findings = [f for f in findings if f.get("confidence", 1.0) >= args.min_confidence]

        if not findings:
            print(f"  {green('✓ No issues found')}\n")
        else:
            print_findings(findings)
            all_findings.extend(findings)

    # ---- summary ----
    if all_findings:
        counts: dict[str, int] = {}
        for f in all_findings:
            counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1

        print(bold(f"Summary: {len(all_findings)} finding(s) in {len(files)} file(s)"))
        for sev in SEVERITY_ORDER:
            if counts.get(sev):
                print(f"  {SEVERITY_COLOR.get(sev, lambda t: t)(sev)}: {counts[sev]}")

        if args.json:
            print("\n" + json.dumps(all_findings, indent=2))
    else:
        print(green("✓ All clear!"))

    # ---- exit code ----
    if args.fail_on != "never":
        blockers = [f for f in all_findings
                    if SEVERITY_ORDER.index(f.get("severity", "info")) <= fail_idx]
        if blockers:
            print(f"\n{red(f'✗ {len(blockers)} blocking finding(s) at {args.fail_on}+ severity')}")
            sys.exit(1)


if __name__ == "__main__":
    main()
