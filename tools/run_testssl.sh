#!/usr/bin/env bash
# Helper script to run testssl.sh with correct PATH on Windows/Git Bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export PATH="${SCRIPT_DIR}/bin:${PATH}"
export TERM=xterm

# Verify hexdump is available
if ! command -v hexdump &>/dev/null; then
    echo "FATAL: hexdump not found in PATH" >&2
    exit 1
fi

exec "${SCRIPT_DIR}/testssl/testssl.sh" "$@"
