#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${STACKMAIL_REPO_URL:-https://github.com/warmidris/stackmail.git}"
INSTALL_ROOT="${STACKMAIL_INSTALL_ROOT:-$HOME/.local/share/stackmail}"
BIN_DIR="${STACKMAIL_BIN_DIR:-$HOME/.local/bin}"
TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

command -v git >/dev/null 2>&1 || {
  echo "git is required" >&2
  exit 1
}

command -v npm >/dev/null 2>&1 || {
  echo "npm is required" >&2
  exit 1
}

rm -rf "$INSTALL_ROOT"
git clone --depth 1 "$REPO_URL" "$TMP_DIR/repo"
mkdir -p "$(dirname "$INSTALL_ROOT")"
mv "$TMP_DIR/repo" "$INSTALL_ROOT"

(
  cd "$INSTALL_ROOT"
  npm install
)

mkdir -p "$BIN_DIR"
ln -sf "$INSTALL_ROOT/bin/stackmail" "$BIN_DIR/stackmail"

cat <<EOF
Stackmail CLI installed.

Add this to your shell profile if needed:
  export PATH="$BIN_DIR:\$PATH"

Then configure a private key:
  export STACKMAIL_PRIVATE_KEY=<your-64-char-hex-key>

And run:
  stackmail inbox
EOF
