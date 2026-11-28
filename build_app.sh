#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="GravityBar.app"
FINAL_APP="$DIR/$APP_NAME"
SWIFT_SRCS=(
    "$DIR/menubar-app/Engine.swift"
    "$DIR/menubar-app/Views.swift"
    "$DIR/menubar-app/main.swift"
)

echo "🔨 Building Apple Silicon (arm64) $APP_NAME..."

if ! command -v swiftc >/dev/null 2>&1; then
    echo "❌ Error: Swift compiler (swiftc) is required. Install Xcode Command Line Tools with: xcode-select --install" >&2
    exit 1
fi

BUILD_DIR="$(mktemp -d "$DIR/.gravitybar-build.XXXXXX")"
APP_DIR="$BUILD_DIR/$APP_NAME"
PREVIOUS_APP="$BUILD_DIR/previous.app"
cleanup() {
    if [ -e "$PREVIOUS_APP" ] && [ ! -e "$FINAL_APP" ]; then
        mv "$PREVIOUS_APP" "$FINAL_APP" || return
    fi
    rm -rf "$BUILD_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

OUT_BIN="$APP_DIR/Contents/MacOS/GravityBar"

echo "✨ Compiling native SwiftUI macOS UI (Apple Silicon arm64)..."
CPU_CORES=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
mkdir -p /tmp/gravitybar_swift_cache
swiftc -O -num-threads "$CPU_CORES" -module-cache-path /tmp/gravitybar_swift_cache -target arm64-apple-macos13.0 "${SWIFT_SRCS[@]}" -o "$OUT_BIN"
chmod +x "$OUT_BIN"

cp "$DIR/switcher_core.py" "$APP_DIR/Contents/Resources/switcher_core.py"
cp "$DIR/LICENSE" "$APP_DIR/Contents/Resources/LICENSE"
cp "$DIR/THIRD_PARTY_NOTICES" "$APP_DIR/Contents/Resources/THIRD_PARTY_NOTICES"
chmod +x "$APP_DIR/Contents/Resources/switcher_core.py"

ICONSET_DIR="$BUILD_DIR/GravityBarIcon.iconset"
mkdir -p "$ICONSET_DIR"
if "$OUT_BIN" --generate-iconset "$ICONSET_DIR" && command -v iconutil >/dev/null 2>&1; then
    iconutil -c icns "$ICONSET_DIR" -o "$APP_DIR/Contents/Resources/GravityBarIcon.icns"
    cp "$APP_DIR/Contents/Resources/GravityBarIcon.icns" "$APP_DIR/Contents/Resources/AppIcon.icns"
fi

cat << 'PLIST' > "$APP_DIR/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>GravityBar</string>
    <key>CFBundleIdentifier</key>
    <string>com.m4tinbeigi.gravitybar</string>
    <key>CFBundleName</key>
    <string>GravityBar</string>
    <key>CFBundleDisplayName</key>
    <string>GravityBar</string>
    <key>CFBundleIconFile</key>
    <string>GravityBarIcon</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>2.1.3</string>
    <key>CFBundleVersion</key>
    <string>7</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>LSUIElement</key>
    <true/>
    <key>NSUserNotificationAlertStyle</key>
    <string>alert</string>
</dict>
</plist>
PLIST

codesign --force --deep --sign - "$APP_DIR"
codesign --verify --deep --strict "$APP_DIR"

touch "$APP_DIR"
if [ -e "$FINAL_APP" ]; then
    mv "$FINAL_APP" "$PREVIOUS_APP"
fi
mv "$APP_DIR" "$FINAL_APP"
echo "✅ Build complete: $FINAL_APP"
