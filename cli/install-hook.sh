#!/usr/bin/env bash
# Install Odin as a git pre-push hook
# Usage: bash install-hook.sh [/path/to/git/repo]

REPO="${1:-.}"
HOOK_FILE="$REPO/.git/hooks/pre-push"

if [ ! -d "$REPO/.git" ]; then
    echo "Error: $REPO is not a git repository"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cat > "$HOOK_FILE" << EOF
#!/usr/bin/env bash
# Odin pre-push hook — review staged changes before pushing
echo ""
echo "🔍 Odin: Running code review on staged changes..."
echo ""
python3 "$SCRIPT_DIR/odin_review.py" --staged --rules-only --fail-on high
EXIT_CODE=\$?
if [ \$EXIT_CODE -ne 0 ]; then
    echo ""
    echo "❌ Odin found high/critical issues. Fix them or run with --no-verify to skip."
    echo "   To skip: git push --no-verify"
fi
exit \$EXIT_CODE
EOF

chmod +x "$HOOK_FILE"
echo "✅ Odin pre-push hook installed at $HOOK_FILE"
echo ""
echo "The hook will run 'odin_review.py --staged --rules-only' before every push."
echo "Use 'git push --no-verify' to bypass if needed."
