#!/usr/bin/env bash
# Cross-builds cloak.exe + cloak-tray.exe and wraps them in an NSIS
# installer (via Homebrew's makensis) - entirely from macOS/Linux, never
# run against a real Windows machine during development.
#
# What's verified here: the binaries are valid Windows PE executables and
# makensis builds the installer without error. What's NOT verified: that
# the installer actually runs correctly on Windows, that the tray icon
# renders in the notification area, or that Windows SmartScreen's warning
# (expected - this is unsigned) is the only friction a real user hits.
# Treat this as a solid starting point, not a tested release artifact.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v makensis >/dev/null 2>&1; then
	echo "makensis not found - install it with: brew install makensis" >&2
	exit 1
fi

VERSION="${CLOAK_VERSION:-0.1.0}"
DIST_DIR="dist/windows"
BUILD_DIR="$DIST_DIR/build"

rm -rf "$DIST_DIR"
mkdir -p "$BUILD_DIR"

echo "==> Cross-compiling cloak.exe and cloak-tray.exe (version $VERSION)"
# cloak.exe is a CLI tool - keep the default console subsystem so its
# output shows up in whatever terminal launched it. cloak-tray.exe is
# GUI-only - windowsgui suppresses the console window that would
# otherwise flash on launch (and stay open behind the tray icon).
GOOS=windows GOARCH=amd64 go build -o "$BUILD_DIR/cloak.exe" ./cmd/cloak
GOOS=windows GOARCH=amd64 go build -ldflags "-H=windowsgui" -o "$BUILD_DIR/cloak-tray.exe" ./cmd/cloak-tray

file "$BUILD_DIR/cloak.exe" "$BUILD_DIR/cloak-tray.exe" || true

OUT_FILE="$(pwd)/$DIST_DIR/cloak-setup-$VERSION.exe"
echo "==> Building installer with makensis"
makensis \
	-DCLOAK_VERSION="$VERSION" \
	-DBUILD_DIR="$(pwd)/$BUILD_DIR" \
	-DOUT_FILE="$OUT_FILE" \
	scripts/cloak-installer.nsi

echo
echo "Built (unsigned, untested on real Windows): $OUT_FILE"
echo "Also available as plain binaries in: $BUILD_DIR"
echo
echo "Unsigned - Windows SmartScreen will warn 'Windows protected your PC'."
echo "Code signing needs a certificate (~\$100-500/yr from a CA) - a cost decision, not done here."
