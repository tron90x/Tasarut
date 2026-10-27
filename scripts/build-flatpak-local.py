#!/usr/bin/env python3
"""Build a LOCAL test bundle from the existing release binary.

This AI-assisted local packaging script is not a Flathub submission manifest.
The reserved org.example namespace intentionally avoids claiming a publisher.
No SDK, flatpak-builder, network download or host library copying is needed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
APP_ID = "org.example.Tasarut"
BRANCH = "local"
RUNTIME = "org.gnome.Platform"


def run(*args, capture=False):
    result = subprocess.run(
        [str(arg) for arg in args],
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout if capture else ""


def install_file(source, destination, executable=False):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o755 if executable else 0o644)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/tasarut")
    parser.add_argument("--runtime-version", default="51")
    parser.add_argument("--output", type=Path, default=ROOT / "target/flatpak")
    parser.add_argument("--install", action="store_true", help="Install the resulting test app user-wide")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    # This first packaging profile is deliberately architecture-specific.
    with binary.open("rb") as stream:
        elf = stream.read(20)
    if elf[:6] != b"\x7fELF\x02\x01" or int.from_bytes(elf[18:20], "little") != 62:
        raise ValueError("The local profile requires a Linux x86_64 release executable")
    if not shutil.which("flatpak"):
        raise RuntimeError("Install Flatpak before running this script")
    runtime_ref = f"{RUNTIME}/x86_64/{args.runtime_version}"
    run("flatpak", "info", runtime_ref, capture=True)
    version = json.loads((ROOT / "src-tauri/tauri.conf.json").read_text())["version"]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    repository = output / "repo"
    artifact = output / f"Tasarut_{version}_x86_64.flatpak"

    with tempfile.TemporaryDirectory(prefix=".local-build-", dir=output) as scratch:
        work = Path(scratch)
        app = work / "app"
        # A prebuilt local bundle needs only the Platform. Use it as the build
        # image too; a future source build will instead require org.gnome.Sdk.
        run("flatpak", "build-init", "--arch=x86_64", app, APP_ID, RUNTIME, RUNTIME, args.runtime_version)
        files = app / "files"
        # GTK derives its process identity from argv[0] when no Gtk app ID was
        # configured. Match the executable, desktop file and exported icon ID.
        install_file(binary, files / "bin" / APP_ID, executable=True)
        install_file(
            ROOT / "packaging/flatpak" / f"{APP_ID}.desktop",
            files / "share/applications" / f"{APP_ID}.desktop",
        )
        install_file(
            ROOT / "packaging/flatpak" / f"{APP_ID}.metainfo.xml",
            files / "share/metainfo" / f"{APP_ID}.metainfo.xml",
        )
        for size, name in [(32, "32x32.png"), (64, "64x64.png"), (128, "128x128.png"),
                           (256, "128x128@2x.png"), (512, "icon.png")]:
            install_file(
                ROOT / "src-tauri/icons" / name,
                files / f"share/icons/hicolor/{size}x{size}/apps/{APP_ID}.png",
            )
        install_file(ROOT / "public/key.svg", files / f"share/icons/hicolor/scalable/apps/{APP_ID}.svg")

        # Validate against the actual runtime, not this Mint system's ldd result.
        libraries = run("flatpak", "build", "--runtime", "--readonly", "--unshare=network",
                        app, "ldd", f"/app/bin/{APP_ID}", capture=True)
        if "not found" in libraries:
            raise RuntimeError(f"Missing runtime libraries:\n{libraries}")
        run("desktop-file-validate", files / f"share/applications/{APP_ID}.desktop")
        run("flatpak", "build-finish", f"--command={APP_ID}",
            "--socket=wayland", "--socket=fallback-x11", "--share=ipc", "--device=dri",
            "--unshare=network", "--env=GTK_USE_PORTAL=1", app)
        # No --filesystem=home/host, --device=all, host-spawn or broad bus grants.
        metadata = (app / "metadata").read_text()
        run("flatpak", "build-export", "--disable-sandbox", repository, app, BRANCH)
        temporary_bundle = work / artifact.name
        run("flatpak", "build-bundle", "--arch=x86_64",
            "--runtime-repo=https://dl.flathub.org/repo/flathub.flatpakrepo",
            repository, temporary_bundle, APP_ID, BRANCH)
        os.replace(temporary_bundle, artifact)

    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (output / "SHA256SUMS").write_text(f"{digest}  {artifact.name}\n")
    (output / "runtime-libraries.txt").write_text(libraries)
    (output / "flatpak-metadata.txt").write_text(metadata)
    (output / "BUILD-INFO.json").write_text(json.dumps({
        "applicationId": APP_ID,
        "branch": BRANCH,
        "version": version,
        "runtime": runtime_ref,
        "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "bundleSha256": digest,
        "bundleBytes": artifact.stat().st_size,
        "buildMethod": "local repackaging of the existing release ELF; not a source runtime build",
        "filesystemAccess": "file chooser portals; no static home or host access",
        "tpm": "unavailable with default device permissions; no software key fallback",
        "trim": "no additional privilege; kernel/portal may refuse FITRIM",
        "publication": "local testing only; not submitted to Flathub",
    }, ensure_ascii=False, indent=2) + "\n")
    print(f"Local Flatpak bundle: {artifact}", flush=True)
    print(f"SHA-256: {digest}", flush=True)
    if args.install:
        run("flatpak", "install", "--user", "--assumeyes", "--reinstall", "--bundle", artifact)
        print(f"Launch with: flatpak run --user {APP_ID}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Flatpak packaging failed: {error}", file=sys.stderr)
        sys.exit(1)
