#!/usr/bin/env bash
# generate-certs.sh — create self-signed TLS certificates for LOCAL DEVELOPMENT ONLY.
#
# WARNING: These certificates are NOT trusted by browsers and must NEVER be
# used in production. In production, use real certificates (for example from
# Let's Encrypt) and keep private keys secret.
#
# Output (matching the paths used in examples/config.json):
#   assets/server/server.crt
#   assets/server/server.key
#
# The output files are ignored by git (see .gitignore) and are never committed.
#
# Usage:
#   ./scripts/generate-certs.sh          # refuse to overwrite existing files
#   ./scripts/generate-certs.sh --force   # overwrite existing files

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$ROOT_DIR/assets/server"
CRT_FILE="$OUT_DIR/server.crt"
KEY_FILE="$OUT_DIR/server.key"

FORCE=0
if [ "${1:-}" = "--force" ]; then
  FORCE=1
elif [ $# -gt 0 ]; then
  echo "Usage: $0 [--force]" >&2
  exit 2
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "error: openssl is required but was not found in PATH." >&2
  exit 1
fi

if [ "$FORCE" -eq 0 ] && { [ -e "$CRT_FILE" ] || [ -e "$KEY_FILE" ]; }; then
  echo "error: $CRT_FILE and/or $KEY_FILE already exist; refusing to overwrite." >&2
  echo "Delete them first, or re-run with --force." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

openssl req -x509 -newkey rsa:2048 \
  -keyout "$KEY_FILE" -out "$CRT_FILE" \
  -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  2>/dev/null

chmod 600 "$KEY_FILE"
chmod 644 "$CRT_FILE"

echo "WARNING: self-signed development certificates — NOT for production."
echo "Wrote:"
echo "  $CRT_FILE"
echo "  $KEY_FILE"
echo "These files are git-ignored and will not be committed."
