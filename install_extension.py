"""Register GravityBar in existing Antigravity IDE extension profiles."""

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time


LEGACY_IDS = ("m4tinbeigi.antigravity-account-switcher", "m4tinbeigi.gravitybar")


def extension_id(entry):
    if isinstance(entry, dict) and isinstance(entry.get("identifier"), dict):
        return entry["identifier"].get("id")
    return None


def register_extension(source, extensions_dir):
    manifest = json.loads((source / "package.json").read_text(encoding="utf-8"))
    package = f"{manifest['publisher']}.{manifest['name']}"
    version = manifest["version"]
    directory = f"{package}-{version}-arm64"
    target = extensions_dir / directory
    registry = extensions_dir / "extensions.json"
    entries = []
    if registry.exists():
        entries = json.loads(registry.read_text(encoding="utf-8"))
        if not isinstance(entries, list):
            raise ValueError("extensions.json must contain a list")

    entries = [entry for entry in entries if extension_id(entry) not in (package, *LEGACY_IDS)]
    entries.append({
        "identifier": {"id": package},
        "version": version,
        "location": {"$mid": 1, "path": str(target), "scheme": "file"},
        "relativeLocation": directory,
        "metadata": {
            "isApplicationScoped": False,
            "isMachineScoped": False,
            "isBuiltin": False,
            "installedTimestamp": int(time.time() * 1000),
            "pinned": False,
            "source": "custom",
            "id": package,
            "publisherDisplayName": manifest["publisher"],
            "targetPlatform": "universal",
            "updated": False,
            "private": False,
            "isPreReleaseVersion": False,
            "hasPreReleaseVersion": False,
        },
    })

    extensions_dir.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".gravitybar-", dir=extensions_dir) as temp:
        staging = Path(temp)
        shutil.copytree(source, staging / "extension")
        next_registry = staging / "extensions.json"
        with next_registry.open("w", encoding="utf-8") as handle:
            json.dump(entries, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())

        previous = staging / "previous"
        if os.path.lexists(target):
            target.rename(previous)
        try:
            (staging / "extension").rename(target)
            os.replace(next_registry, registry)
        except OSError:
            if target.exists():
                target.rename(staging / "extension")
            if os.path.lexists(previous):
                previous.rename(target)
            raise


def main(source):
    home = Path.home()
    profiles = [home / name for name in (".antigravity-ide", ".antigravity") if (home / name).is_dir()]
    if not profiles:
        print("No existing Antigravity IDE profile. Extension registration skipped.")
    failure = False
    for profile in profiles:
        try:
            register_extension(source, profile / "extensions")
            print(f"✓ Editor status bar extension registered in {profile / 'extensions'}")
        except (OSError, ValueError, KeyError) as exc:
            print(f"Could not register GravityBar in {profile}: {exc}", file=sys.stderr)
            failure = True
    return int(failure)


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]).resolve()))
