#!/bin/sh
# SonuShield installer.
#
# Installs a pinned SonuShield release binary. Safe to inspect
# before running: this script is linear, uses no eval, runs no
# downloaded code except the release binary's own `version`
# check, and downloads exactly two files whose URLs it prints
# before fetching: the release tarball and its SHA-256 checksum
# file. The tarball is verified against the checksum before
# anything is extracted, and only the single expected binary is
# extracted from it.
#
# Usage:
#   ./install.sh --version v0.1.0 [--prefix DIR] [--dry-run]
#   SONUSHIELD_VERSION=v0.1.0 ./install.sh
#
# The version is required and must be an exact release tag:
# there is no "latest", so an install can never silently float
# to an unreviewed release. No releases are published yet; until
# the first release exists, build from source instead:
#   git clone https://github.com/sonudigitalmindset-design/SonuShield
#   cd SonuShield && go build -o sonushield .
#
# Release layout (what the release workflow must publish):
#   sonushield-<os>-<arch>.tar.gz        (one file: ./sonushield)
#   sonushield-<os>-<arch>.tar.gz.sha256 (sha256sum output)
# for linux/darwin x amd64/arm64.
#
# Checksums verify download integrity against the published
# checksum file; they do not prove authorship. For high-assurance
# installs, compare the checksum on the GitHub release page in
# your browser before running this script.
#
# SONUSHIELD_RELEASE_BASE_URL overrides the download base URL
# (default: the GitHub releases download URL below). It exists
# for private mirrors and tests; only point it at infrastructure
# you trust, and note the script always prints the full URLs.
#
# The script never uses sudo itself. If the install directory is
# not writable, re-run with sudo or pass --prefix to a directory
# you own.

set -eu

PROG="sonushield"
REPO="sonudigitalmindset-design/SonuShield"
DEFAULT_BASE_URL="https://github.com/${REPO}/releases/download"
BASE_URL="${SONUSHIELD_RELEASE_BASE_URL:-$DEFAULT_BASE_URL}"

VERSION="${SONUSHIELD_VERSION:-}"
PREFIX="/usr/local"
DRY_RUN=0

usage_text() {
    echo "Usage: $0 --version vX.Y.Z [--prefix DIR] [--dry-run]"
    echo "  --version   exact release tag to install (required; or SONUSHIELD_VERSION)"
    echo "  --prefix    install prefix, binary goes to DIR/bin/sonushield (default /usr/local)"
    echo "  --dry-run   print what would happen without downloading or installing"
}

usage() {
    usage_text >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            [ $# -ge 2 ] || usage
            VERSION="$2"
            shift 2
            ;;
        --version=*)
            VERSION="${1#--version=}"
            shift
            ;;
        --prefix)
            [ $# -ge 2 ] || usage
            PREFIX="$2"
            shift 2
            ;;
        --prefix=*)
            PREFIX="${1#--prefix=}"
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage_text
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage
            ;;
    esac
done

if [ -z "$VERSION" ]; then
    echo "No version given. Pass --version vX.Y.Z with an exact release tag." >&2
    usage
fi
# A pinned version is mandatory, and must look like a release tag
# (vMAJOR.MINOR.PATCH, optional -suffix). The character guard
# keeps slashes, whitespace, quotes, and shell metacharacters
# out of the download URL; the shape guard keeps the tag plausible.
case "$VERSION" in
    *..*|*[!A-Za-z0-9._-]*)
        echo "Invalid version: $VERSION." >&2
        exit 2
        ;;
esac
case "$VERSION" in
    v[0-9]*.[0-9]*.[0-9]*|v[0-9]*.[0-9]*.[0-9]*-*)
        ;;
    *)
        echo "Invalid version: $VERSION (expected vMAJOR.MINOR.PATCH)." >&2
        exit 2
        ;;
esac

# Platform detection.
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
    Linux) OS="linux" ;;
    Darwin) OS="darwin" ;;
    *)
        echo "Unsupported OS: $OS. Build from source instead (see the script header)." >&2
        exit 1
        ;;
esac
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
        echo "Unsupported architecture: $ARCH. Build from source instead (see the script header)." >&2
        exit 1
        ;;
esac

ARTIFACT="${PROG}-${OS}-${ARCH}.tar.gz"
ARTIFACT_URL="${BASE_URL}/${VERSION}/${ARTIFACT}"
CHECKSUM_URL="${ARTIFACT_URL}.sha256"
TARGET="${PREFIX}/bin/${PROG}"

echo "SonuShield installer"
echo "  version:  ${VERSION}"
echo "  platform: ${OS}/${ARCH}"
echo "  tarball:  ${ARTIFACT_URL}"
echo "  checksum: ${CHECKSUM_URL}"
echo "  target:   ${TARGET}"

if [ "$DRY_RUN" -eq 1 ]; then
    echo "Dry run: nothing downloaded or installed."
    exit 0
fi

# Download tool: curl preferred, wget fallback. Both fail on
# HTTP errors, so a missing release aborts instead of saving an
# error page as the "tarball".
if command -v curl >/dev/null 2>&1; then
    DOWNLOAD="curl -fL --retry 2 -o"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOAD="wget -q -O"
else
    echo "Neither curl nor wget is installed. Install one and retry." >&2
    exit 1
fi

# Checksum tool: sha256sum (Linux) or shasum (macOS).
if command -v sha256sum >/dev/null 2>&1; then
    CHECKSUM_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    CHECKSUM_CMD="shasum -a 256"
else
    echo "Neither sha256sum nor shasum is installed. Install one and retry." >&2
    exit 1
fi

command -v tar >/dev/null 2>&1 || { echo "tar is required but not installed." >&2; exit 1; }

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

cd "$TMPDIR"

echo "Downloading ${ARTIFACT_URL} ..."
# shellcheck disable=SC2086
$DOWNLOAD "${ARTIFACT}" "${ARTIFACT_URL}" || {
    echo "Download failed. Is ${VERSION} a published release? Check:" >&2
    echo "  https://github.com/${REPO}/releases" >&2
    exit 1
}
echo "Downloading ${CHECKSUM_URL} ..."
# shellcheck disable=SC2086
$DOWNLOAD "${ARTIFACT}.sha256" "${CHECKSUM_URL}" || {
    echo "Checksum download failed." >&2
    exit 1
}

[ -s "${ARTIFACT}.sha256" ] || { echo "Checksum file is empty." >&2; exit 1; }

echo "Verifying checksum ..."
# shellcheck disable=SC2086
$CHECKSUM_CMD -c "${ARTIFACT}.sha256" || {
    echo "CHECKSUM MISMATCH: the download does not match its published checksum. Aborting; nothing was installed." >&2
    exit 1
}

echo "Inspecting tarball contents ..."
CONTENTS="$(tar -tzf "${ARTIFACT}")"
if [ "$CONTENTS" != "./${PROG}" ] && [ "$CONTENTS" != "${PROG}" ]; then
    echo "Unexpected tarball contents (expected exactly one file, ${PROG}):" >&2
    echo "$CONTENTS" >&2
    exit 1
fi

echo "Extracting ${PROG} ..."
if [ "$CONTENTS" = "./${PROG}" ]; then
    tar -xzf "${ARTIFACT}" "./${PROG}"
else
    tar -xzf "${ARTIFACT}" "${PROG}"
fi
chmod +x "${PROG}"

echo "Smoke-checking the binary ..."
if ! "./${PROG}" version >/dev/null 2>&1; then
    echo "The downloaded binary failed its version check. Aborting; nothing was installed." >&2
    exit 1
fi

if [ ! -d "${PREFIX}/bin" ]; then
    mkdir -p "${PREFIX}/bin" || {
        echo "Cannot create ${PREFIX}/bin. Re-run with sudo or pass --prefix to a directory you own." >&2
        exit 1
    }
fi
if [ ! -w "${PREFIX}/bin" ]; then
    echo "${PREFIX}/bin is not writable. Re-run with sudo or pass --prefix to a directory you own." >&2
    exit 1
fi

echo "Installing to ${TARGET} ..."
cp "${PROG}" "${TARGET}.new"
chmod 0755 "${TARGET}.new"
mv "${TARGET}.new" "${TARGET}"

echo "Installed ${TARGET}"
"${TARGET}" version
echo ""
echo "Next steps:"
echo "  ${TARGET} --wizard        first-run web setup (no config.json yet)"
echo "  ${TARGET} validate        check a config file"
echo "  ${TARGET} help            all subcommands"
