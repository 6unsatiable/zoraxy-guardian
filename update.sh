#!/usr/bin/env bash
# update.sh — install or update the Guardian plugin on a Zoraxy host.
#
# Run this ON THE ZORAXY HOST (the machine where the container's plugins
# directory is bind-mounted from the host filesystem).
#
# It will:
#   1. Fetch the latest binary from GitHub releases (rolling 'latest' tag).
#   2. Verify it runs (with -introspect).
#   3. Find the existing Guardian install in <plugins-dir> (any folder name -
#      Zoraxy's plugin-directory installer uses "Guardian/Guardian") and
#      atomically swap the new binary in, keeping the old one as *.bak.
#      A fresh install goes to <plugins-dir>/Guardian/Guardian.
#   4. Print a reminder to restart your Zoraxy container manually.
#
# Usage:
#   ./update.sh [--dir <plugins-dir>] [--version <tag>] [--arch <amd64|arm64|arm>]
#
# Defaults:
#   --dir       $ZORAXY_PLUGINS_DIR, else the first that exists of
#               /opt/zoraxy/plugin (Docker image) and /opt/zoraxy/plugins
#   --version   latest                (the rolling main-branch release)
#   --arch      auto-detected via uname -m
#
# Examples:
#   ZORAXY_PLUGINS_DIR=/srv/zoraxy/plugin ./update.sh
#   ./update.sh --dir /opt/zoraxy/plugin --version v0.3.0

set -euo pipefail

PLUGINS_DIR="${ZORAXY_PLUGINS_DIR:-}"
VERSION="latest"
ARCH=""
REPO="6unsatiable/zoraxy-guardian"
PLUGIN_ID="com.guardian.zoraxy"
PLUGIN_NAME="Guardian"

while [ $# -gt 0 ]; do
    case "$1" in
        --dir)     PLUGINS_DIR="$2"; shift 2 ;;
        --version) VERSION="$2";     shift 2 ;;
        --arch)    ARCH="$2";        shift 2 ;;
        -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
        *)         echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$ARCH" ]; then
    case "$(uname -m)" in
        x86_64|amd64) ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64 ;;
        armv7l|armv6l) ARCH=arm   ;;
        *) echo "unable to auto-detect architecture from $(uname -m); pass --arch" >&2; exit 1 ;;
    esac
fi

step() { printf "\n\033[1;34m==>\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m✓\033[0m %s\n" "$*"; }
die()  { printf "\033[1;31m✗\033[0m %s\n" "$*" >&2; exit 1; }

if [ -z "$PLUGINS_DIR" ]; then
    for d in /opt/zoraxy/plugin /opt/zoraxy/plugins; do
        if [ -d "$d" ]; then PLUGINS_DIR="$d"; break; fi
    done
    [ -n "$PLUGINS_DIR" ] || die "no plugin directory found; pass --dir <host path mounted at /opt/zoraxy/plugin>"
fi
[ -d "$PLUGINS_DIR" ] || die "plugin directory ${PLUGINS_DIR} does not exist"

ASSET="linux_${ARCH}_guardian"

# Update the binary Zoraxy actually runs. Installing next to it under another
# folder name would leave two copies with the same plugin ID.
TARGET=""
for f in "$PLUGINS_DIR"/*/*; do
    [ -f "$f" ] && [ -x "$f" ] || continue
    case "$f" in *.bak|*.new|*.tmp) continue ;; esac
    if timeout 10 "$f" -introspect 2>/dev/null | grep -q "\"${PLUGIN_ID}\""; then
        TARGET="$f"
        break
    fi
done
if [ -n "$TARGET" ]; then
    ok "existing install: ${TARGET}"
else
    TARGET="${PLUGINS_DIR}/${PLUGIN_NAME}/${PLUGIN_NAME}"
    ok "no existing install; installing to ${TARGET}"
fi
TARGET_DIR="$(dirname "$TARGET")"

step "Resolving release ${VERSION} for ${ASSET}"
if [ "$VERSION" = "latest" ]; then
    # The rolling pre-release uses tag 'latest'.
    API_URL="https://api.github.com/repos/${REPO}/releases/tags/latest"
else
    API_URL="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
fi

DOWNLOAD_URL=$(curl -fsSL "$API_URL" \
    | python3 -c "import json,sys; r=json.load(sys.stdin); [print(a['browser_download_url']) for a in r.get('assets', []) if a['name']=='${ASSET}']" \
    | head -1)
[ -n "$DOWNLOAD_URL" ] || die "asset ${ASSET} not found in release ${VERSION}. Check ${API_URL}"
ok "found ${DOWNLOAD_URL##*/}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

step "Downloading"
curl -fsSL -o "${TMP}/${PLUGIN_NAME}" "$DOWNLOAD_URL" || die "download failed"
chmod +x "${TMP}/${PLUGIN_NAME}"
ok "downloaded $(wc -c < "${TMP}/${PLUGIN_NAME}") bytes"

step "Verifying binary"
if ! "${TMP}/${PLUGIN_NAME}" -introspect 2>/dev/null | grep -q "\"${PLUGIN_ID}\""; then
    die "downloaded binary fails -introspect; refusing to install"
fi
ok "introspect ok"

step "Installing to ${TARGET}"
mkdir -p "$TARGET_DIR"
# Atomic swap: move into place via rename (same filesystem as $TARGET_DIR).
TMP_DEST="${TARGET}.new"
cp "${TMP}/${PLUGIN_NAME}" "$TMP_DEST"
chmod +x "$TMP_DEST"
if [ -f "$TARGET" ]; then
    cp -p "$TARGET" "${TARGET}.bak"
    ok "previous binary kept as ${TARGET}.bak"
fi
mv -f "$TMP_DEST" "$TARGET"
ok "installed"

cat <<EOF

Done. The binary is in place at:
  $TARGET

Now restart your Zoraxy container so the new plugin is picked up. Examples:
  docker restart <zoraxy-container-name>
  docker compose -f /path/to/compose.yml restart zoraxy

After restart, open Zoraxy's web UI → Plugins → enable "Guardian" (if not
already enabled) → assign to your HTTP Proxy Rule tag(s).
EOF
