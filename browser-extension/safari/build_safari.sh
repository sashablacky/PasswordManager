#!/bin/sh
# Builds the Xcode project of the SecureVault Safari extension (run on a Mac with Xcode).
#
#   sh browser-extension/safari/build_safari.sh
#
# Then open the project it prints, choose your Apple ID under
# Signing & Capabilities (both targets) and press Run. See ../README.md.
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
EXTENSION="$HERE/../extension"
OUT="$HERE/build"
APP_NAME="SecureVault for Safari"
BUNDLE_ID="io.github.sashablacky.securevault.safari"
APP_GROUP='$(TeamIdentifierPrefix)securevault.bridge'

rm -rf "$OUT"
xcrun safari-web-extension-converter "$EXTENSION" \
    --project-location "$OUT" --app-name "$APP_NAME" --bundle-identifier "$BUNDLE_ID" \
    --swift --macos-only --copy-resources --no-prompt --no-open --force

HANDLER="$(find "$OUT" -name SafariWebExtensionHandler.swift | head -n 1)"
EXT_DIR="$(dirname "$HANDLER")"
cp "$HERE/SafariWebExtensionHandler.swift" "$HANDLER"

# The handler finds the program's socket through this App Group
PLIST="$EXT_DIR/Info.plist"
/usr/libexec/PlistBuddy -c "Delete :SecureVaultAppGroup" "$PLIST" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Add :SecureVaultAppGroup string $APP_GROUP" "$PLIST"

ENTITLEMENTS="$(find "$EXT_DIR" -name '*.entitlements' | head -n 1)"
/usr/libexec/PlistBuddy -c "Delete :com.apple.security.application-groups" "$ENTITLEMENTS" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Add :com.apple.security.application-groups array" "$ENTITLEMENTS"
/usr/libexec/PlistBuddy -c "Add :com.apple.security.application-groups:0 string $APP_GROUP" "$ENTITLEMENTS"

echo
echo "Project: $(find "$OUT" -name '*.xcodeproj' -maxdepth 2 | head -n 1)"
echo "Open it in Xcode, pick your Apple ID as the team for both targets, then Product > Run."
