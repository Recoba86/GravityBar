#!/bin/bash
set -e

OS="$(uname -s)"
ARCH="$(uname -m)"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 Installing GravityBar (Antigravity Account Switcher)..."

if [ "$OS" = "Darwin" ]; then
    if [ "$ARCH" != "arm64" ]; then
        echo "❌ Unsupported architecture: $ARCH. GravityBar requires macOS on Apple Silicon (M1/M2/M3/M4 - arm64)." >&2
        exit 1
    fi
    echo "🍏 Detected Platform: macOS on Apple Silicon (M1/M2/M3/M4 - arm64)"

    # Build Apple Silicon (arm64) macOS app
    "$DIR/build_app.sh"

    DEST="/Applications/GravityBar.app"
    DESKTOP_DEST="$HOME/Desktop/GravityBar.app"

    if pgrep -u "$UID" -x GravityBar >/dev/null; then
        pkill -TERM -u "$UID" -x GravityBar || true
        for _ in {1..20}; do
            pgrep -u "$UID" -x GravityBar >/dev/null || break
            sleep 0.25
        done
        if pgrep -u "$UID" -x GravityBar >/dev/null; then
            echo "GravityBar is still running. Quit it before installing." >&2
            exit 1
        fi
    fi

    install_bundle() (
        local destination="$1" stage
        stage="$(mktemp -d "$(dirname "$destination")/.gravitybar-install.XXXXXX")"
        # shellcheck disable=SC2329
        cleanup() {
            if [ -e "$stage/previous.app" ] && [ ! -e "$destination" ]; then
                mv "$stage/previous.app" "$destination" || return
            fi
            rm -rf "$stage"
        }
        trap cleanup EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
        ditto "$DIR/GravityBar.app" "$stage/GravityBar.app"
        codesign --verify --deep --strict "$stage/GravityBar.app"
        if [ -e "$destination" ]; then
            mv "$destination" "$stage/previous.app"
        fi
        mv "$stage/GravityBar.app" "$destination"
    )

    echo "📦 Installing GravityBar.app to /Applications and ~/Desktop..."
    install_bundle "$DEST"
    mkdir -p "$HOME/Desktop"
    install_bundle "$DESKTOP_DEST"

    NEW_PLIST="$HOME/Library/LaunchAgents/com.m4tinbeigi.gravitybar.plist"
    MIGRATE_LAUNCH_AGENT=false
    for LEGACY_PLIST in \
        "$HOME/Library/LaunchAgents/com.m4tinbeigi.antigravitymenubar.plist" \
        "$HOME/Library/LaunchAgents/com.m4tinbeigi.antigravityswitcher.plist"
    do
        if [ -f "$LEGACY_PLIST" ]; then
            MIGRATE_LAUNCH_AGENT=true
        fi
    done
    if [ "$MIGRATE_LAUNCH_AGENT" = true ]; then
        mkdir -p "$HOME/Library/LaunchAgents"
        STAGED_PLIST="$(mktemp "$NEW_PLIST.XXXXXX")"
        cat << 'LPLIST' > "$STAGED_PLIST"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.m4tinbeigi.gravitybar</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/GravityBar.app/Contents/MacOS/GravityBar</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
LPLIST
        plutil -lint "$STAGED_PLIST" >/dev/null
        mv -f "$STAGED_PLIST" "$NEW_PLIST"
        rm -f "$HOME/Library/LaunchAgents/com.m4tinbeigi.antigravitymenubar.plist" \
              "$HOME/Library/LaunchAgents/com.m4tinbeigi.antigravityswitcher.plist"
        echo "✓ Migrated Launch at Login agent to GravityBar.app"
    fi

    CLI_TARGET="$DEST/Contents/Resources/switcher_core.py"
    install_cli_links() {
        local bin_dir="$1" name existing
        for name in gravitybar agy-switch; do
            if [ -e "$bin_dir/$name" ] || [ -L "$bin_dir/$name" ]; then
                existing="$(readlink "$bin_dir/$name" || true)"
                if [ "$existing" != "$CLI_TARGET" ] && [ "$existing" != "$DIR/switcher_core.py" ]; then
                    echo "CLI shortcut already exists at $bin_dir/$name; leaving it in place." >&2
                    return 1
                fi
            fi
        done
        ln -sf "$CLI_TARGET" "$bin_dir/gravitybar" || return 1
        ln -sf "$CLI_TARGET" "$bin_dir/agy-switch" || return 1
        echo "✓ CLI shortcuts registered in $bin_dir (gravitybar, agy-switch)"
    }

    INSTALLED_CLI=false
    for BIN_DIR in "/opt/homebrew/bin" "/usr/local/bin" "$HOME/.local/bin"; do
        if [ "$BIN_DIR" = "$HOME/.local/bin" ]; then mkdir -p "$BIN_DIR"; fi
        if [ -d "$BIN_DIR" ] && [ -w "$BIN_DIR" ] && install_cli_links "$BIN_DIR"; then
            INSTALLED_CLI=true
            case ":$PATH:" in
                *":$BIN_DIR:"*) ;;
                *) echo "Add $BIN_DIR to your PATH to use the CLI shortcuts by name." ;;
            esac
            break
        fi
    done
    if [ "$INSTALLED_CLI" = false ]; then
        echo "No CLI shortcuts installed. The CLI is available at $CLI_TARGET." >&2
    fi
else
    echo "❌ Unsupported operating system: $OS. GravityBar supports macOS on Apple Silicon (arm64)." >&2
    exit 1
fi

open "$DEST"
echo "✓ GravityBar installed on $OS ($ARCH) and launch requested."

# Register the extension only in existing Antigravity profiles.
python3 "$DIR/install_extension.py" "$DIR/editor-extension"
