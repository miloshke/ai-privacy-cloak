#!/usr/bin/env bash
# Builds cloak-tray.app (bundling the cloak CLI alongside it) and wraps
# it into a .dmg for distribution.
#
# Unsigned by default - Gatekeeper will show an "Apple could not verify
# this app is free of malware" warning on first open (right-click ->
# Open bypasses it once per machine).
#
# To produce a signed + notarized build instead, set both:
#   CLOAK_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
#   CLOAK_NOTARY_PROFILE="<profile name>"
# One-time setup for both, done once in Keychain Access / Terminal on a
# machine with the Apple Developer Program membership:
#   1. Create a "Developer ID Application" certificate: Xcode ->
#      Settings -> Accounts -> Manage Certificates -> "+" -> Developer ID
#      Application. It lands in your login Keychain automatically.
#   2. Find its exact identity string: `security find-identity -v -p codesigning`
#   3. Store notarization credentials once:
#      `xcrun notarytool store-credentials "<profile name>" --apple-id you@example.com --team-id TEAMID --password <app-specific password>`
#      (the app-specific password comes from https://appleid.apple.com,
#      not your regular Apple ID password; the team ID is on
#      developer.apple.com/account under Membership).
# After that, both env vars above are all this script needs - nothing
# else changes.
set -euo pipefail
cd "$(dirname "$0")/.."

APP_NAME="cloak-tray"
BUNDLE_ID="dev.cloak.tray"
VERSION="${CLOAK_VERSION:-0.1.0}"
DIST_DIR="dist/macos"
APP_DIR="$DIST_DIR/$APP_NAME.app"

SIGN_IDENTITY="${CLOAK_SIGN_IDENTITY:-}"
NOTARY_PROFILE="${CLOAK_NOTARY_PROFILE:-}"

rm -rf "$DIST_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

echo "==> Building cloak-tray and cloak (version $VERSION)"
go build -ldflags "-X main.version=$VERSION" -o "$APP_DIR/Contents/MacOS/cloak-tray" ./cmd/cloak-tray
go build -ldflags "-X main.version=$VERSION" -o "$APP_DIR/Contents/MacOS/cloak" ./cmd/cloak

cat >"$APP_DIR/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>cloak</string>
	<key>CFBundleDisplayName</key>
	<string>cloak</string>
	<key>CFBundleIdentifier</key>
	<string>$BUNDLE_ID</string>
	<key>CFBundleVersion</key>
	<string>$VERSION</string>
	<key>CFBundleShortVersionString</key>
	<string>$VERSION</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleExecutable</key>
	<string>cloak-tray</string>
	<key>LSUIElement</key>
	<true/>
	<key>LSMinimumSystemVersion</key>
	<string>11.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
</dict>
</plist>
PLIST

if [ -n "$SIGN_IDENTITY" ]; then
  echo "==> Signing binaries and bundle ($SIGN_IDENTITY)"
  # Sign the nested executables first, then the bundle itself - Apple
  # recommends against --deep for anything beyond trivial bundles, since
  # it can silently skip or mis-sign nested content.
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP_DIR/Contents/MacOS/cloak"
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP_DIR/Contents/MacOS/cloak-tray"
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP_DIR"
  codesign --verify --deep --strict --verbose=2 "$APP_DIR"
fi

echo "==> Assembling .dmg"
DMG_STAGING="$DIST_DIR/dmg-staging"
mkdir -p "$DMG_STAGING"
cp -R "$APP_DIR" "$DMG_STAGING/"
ln -s /Applications "$DMG_STAGING/Applications"

DMG_PATH="$DIST_DIR/cloak-$VERSION.dmg"
hdiutil create -volname "cloak" -srcfolder "$DMG_STAGING" -ov -format UDZO "$DMG_PATH" -quiet
rm -rf "$DMG_STAGING"

if [ -n "$SIGN_IDENTITY" ]; then
  echo "==> Signing .dmg"
  codesign --force --sign "$SIGN_IDENTITY" "$DMG_PATH"
fi

if [ -n "$SIGN_IDENTITY" ] && [ -n "$NOTARY_PROFILE" ]; then
  echo "==> Submitting for notarization (this polls Apple and can take a few minutes)"
  xcrun notarytool submit "$DMG_PATH" --keychain-profile "$NOTARY_PROFILE" --wait
  echo "==> Stapling notarization ticket"
  xcrun stapler staple "$DMG_PATH"
  echo "==> Gatekeeper assessment"
  spctl --assess --type open --context context:primary-signature -v "$DMG_PATH" || \
    echo "    (spctl assessment command failed to run on this macOS version - not fatal; the staple above is the part that matters)"
elif [ -n "$SIGN_IDENTITY" ]; then
  echo "NOTE: signed but not notarized - set CLOAK_NOTARY_PROFILE too, otherwise Gatekeeper will still warn."
fi

sha256sum "$DMG_PATH" 2>/dev/null || shasum -a 256 "$DMG_PATH"

echo
echo "Built:"
echo "  App: $APP_DIR"
echo "  Dmg: $DMG_PATH"
echo
if [ -n "$SIGN_IDENTITY" ] && [ -n "$NOTARY_PROFILE" ]; then
  echo "Signed and notarized - opens cleanly on a fresh Mac with no Gatekeeper warning."
elif [ -n "$SIGN_IDENTITY" ]; then
  echo "Signed but not notarized - Gatekeeper will still warn. Set CLOAK_NOTARY_PROFILE too."
else
  echo "Unsigned - Gatekeeper will warn on first open (right-click -> Open bypasses it)."
  echo "Set CLOAK_SIGN_IDENTITY and CLOAK_NOTARY_PROFILE to sign + notarize; see the comment at the top of this script."
fi
