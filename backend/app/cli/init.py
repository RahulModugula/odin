"""odin init — set up Odin in the current repository."""

from __future__ import annotations

import argparse
import stat
import subprocess
import sys
from pathlib import Path

_DEFAULT_ODIN_YAML = """\
# Odin configuration — https://github.com/RahulModugula/odin
# This file controls how Odin reviews your code.

provider: default          # LLM provider: default | openrouter | lmstudio | ollama
rules_enabled: true        # deterministic rules (instant, zero cost)
dataflow_enabled: true     # taint analysis + LLM triage

# Ignore patterns (glob)
ignore:
  - "*.min.js"
  - "vendor/**"
  - "node_modules/**"
  - "**/*.generated.*"

# Quality gate — block PRs that fail
quality_gate:
  enabled: false
  min_score: 70
  max_critical: 0
  max_high: 2

# Suppression thresholds
feedback:
  general_threshold: 3     # FP reports before auto-suppression
  taint_threshold: 2       # taint-pair FP reports before suppression
"""

_PRE_PUSH_HOOK = """\
#!/bin/sh
# Odin pre-push hook — review changed files before pushing
# Install: odin init --hook
# Bypass: git push --no-verify

echo "🔍 Odin pre-push review..."
odin review --diff HEAD~1 --rules-only --fail-on high --quiet
"""

_GITHUB_ACTION = """\
name: Odin Code Review
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  odin-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Odin
        run: pip install odin-code-review

      - name: Run Odin (rules-only)
        run: odin review --diff origin/main --rules-only --sarif > odin-results.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: odin-results.sarif
          category: odin
"""


def run_init(args: argparse.Namespace | None = None) -> None:
    """Set up Odin in the current repository."""
    project_root = _find_git_root()
    if project_root is None:
        print("Error: not in a git repository. Run `git init` first.")
        sys.exit(1)

    created = []

    # Create .odin.yaml
    odin_yaml = project_root / ".odin.yaml"
    if not odin_yaml.exists():
        odin_yaml.write_text(_DEFAULT_ODIN_YAML)
        created.append(".odin.yaml")
        print(f"  ✓ Created {odin_yaml}")
    else:
        print(f"  · {odin_yaml} already exists, skipping")

    # Create GitHub Action
    workflows_dir = project_root / ".github" / "workflows"
    odin_action = workflows_dir / "odin.yml"
    if not odin_action.exists():
        workflows_dir.mkdir(parents=True, exist_ok=True)
        odin_action.write_text(_GITHUB_ACTION)
        created.append(".github/workflows/odin.yml")
        print(f"  ✓ Created {odin_action}")
    else:
        print(f"  · {odin_action} already exists, skipping")

    # Set up pre-push hook (opt-in via --hook flag)
    if args and getattr(args, "hook", False):
        hooks_dir = project_root / ".git" / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        hook_path = hooks_dir / "pre-push"
        if not hook_path.exists():
            hook_path.write_text(_PRE_PUSH_HOOK)
            hook_path.chmod(hook_path.stat().st_mode | stat.S_IEXEC)
            created.append(".git/hooks/pre-push")
            print("  ✓ Installed pre-push hook")
        else:
            print("  · pre-push hook already exists, skipping")

    if created:
        print(f"\n  Odin initialized! Created: {', '.join(created)}")
        print("  Next: run `odin review .` to try it out")
    else:
        print("\n  Odin is already set up in this repository")


def _find_git_root() -> Path | None:
    """Walk up to find the .git directory."""
    try:
        result = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        return Path(result)
    except subprocess.CalledProcessError:
        return None
