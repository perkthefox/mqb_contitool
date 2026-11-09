#!/usr/bin/env python3
"""Cross-platform standalone release builder for ContiTool (.exe / .app / .dmg / .zip).

Usage:
  python3 scripts/build_release.py
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import zipfile

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
sys.path.insert(0, str(SRC_DIR))

from contitool import __version__  # noqa: E402

# Shipped in every archive: ContiTool's license and the licenses of what the build bundles (Qt and python-can are
# LGPL-3.0, which must travel with them together with the GPL-3.0 it builds on).
LEGAL_FILES = ("LICENSE", "THIRD_PARTY_NOTICES.md", "LICENSES")


def _generate_icons(icon_dir: Path) -> Path | None:
    """Render PNG/ICO/ICNS icons headlessly via PySide6 QPainter so zero external image libs are required."""
    icon_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    png_256 = icon_dir / "contitool_256.png"
    helper = (
        "import sys; sys.path.insert(0, %r); "
        "from PySide6.QtGui import QGuiApplication; "
        "from contitool.gui.theme import build_app_icon; "
        "app = QGuiApplication([]); "
        "ic = build_app_icon(); "
        "ic.pixmap(256, 256).save(%r, 'PNG')"
    ) % (str(SRC_DIR), str(png_256))
    subprocess.run([sys.executable, "-c", helper], env=env, check=True)

    sys_name = platform.system()
    if sys_name == "Windows":
        # Embed 256x256 PNG directly inside a standard Windows ICO container
        png_bytes = png_256.read_bytes()
        ico_path = icon_dir / "ContiTool.ico"
        header = struct.pack("<HHH", 0, 1, 1)
        entry = struct.pack("<BBBBHHII", 0, 0, 0, 0, 1, 32, len(png_bytes), 6 + 16)
        ico_path.write_bytes(header + entry + png_bytes)
        return ico_path

    if sys_name == "Darwin" and shutil.which("sips") and shutil.which("iconutil"):
        iconset = icon_dir / "ContiTool.iconset"
        if iconset.exists():
            shutil.rmtree(iconset)
        iconset.mkdir(parents=True)
        for sz in (16, 32, 128, 256):
            subprocess.run(
                ["sips", "-z", str(sz), str(sz), str(png_256), "--out", str(iconset / f"icon_{sz}x{sz}.png")],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            subprocess.run(
                ["sips", "-z", str(sz * 2), str(sz * 2), str(png_256), "--out", str(iconset / f"icon_{sz}x{sz}@2x.png")],
                check=True,
                stdout=subprocess.DEVNULL,
            )
        icns_path = icon_dir / "ContiTool.icns"
        subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(icns_path)], check=True)
        return icns_path

    return png_256


def _zip_directory(source_dir: Path, zip_path: Path, arc_prefix: str = "") -> None:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(source_dir.rglob("*")):
            rel = item.relative_to(source_dir)
            arcname = f"{arc_prefix}/{rel.as_posix()}" if arc_prefix else rel.as_posix()
            if item.is_symlink():
                # Preserve macOS Framework symlinks cleanly inside zip
                zi = zipfile.ZipInfo(arcname)
                zi.create_system = 3
                zi.external_attr = 0o120755 << 16
                zf.writestr(zi, os.readlink(item))
            elif item.is_file():
                zf.write(item, arcname)


def build() -> None:
    import PyInstaller.__main__

    build_dir = ROOT_DIR / "build"
    dist_dir = ROOT_DIR / "dist"
    rel_dir = dist_dir / "release"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    rel_dir.mkdir(parents=True, exist_ok=True)

    icon_path = _generate_icons(build_dir / "icons")
    sys_name = platform.system()
    arch = platform.machine().lower()

    pyi_args = [
        str(ROOT_DIR / "conti_cp_tool.py"),
        "--name=ContiTool",
        "--noconfirm",
        "--clean",
        "--windowed",
        f"--paths={SRC_DIR}",
        f"--distpath={dist_dir}",
        f"--workpath={build_dir / 'pyi'}",
        f"--specpath={build_dir}",
        "--collect-submodules=can.interfaces",
        "--hidden-import=serial.tools.list_ports",
    ]
    # inside the bundle, so they are part of what PyInstaller signs on macOS
    pyi_args += [f"--add-data={ROOT_DIR / name}{os.pathsep}{name if name == 'LICENSES' else '.'}" for name in LEGAL_FILES]
    if sys_name == "Darwin":
        pyi_args.append("--osx-bundle-identifier=com.perkthefox.contitool")
    if icon_path is not None and icon_path.suffix in (".ico", ".icns"):
        pyi_args.append(f"--icon={icon_path}")

    print(f"[build] Running PyInstaller for ContiTool v{__version__} ({sys_name}/{arch})...")
    PyInstaller.__main__.run(pyi_args)

    if sys_name == "Darwin":
        app_bundle = dist_dir / "ContiTool.app"
        if not app_bundle.exists():
            raise RuntimeError(f"Expected macOS bundle not found: {app_bundle}")
        zip_out = rel_dir / f"ContiTool-v{__version__}-macos-{arch}.zip"
        _zip_directory(app_bundle, zip_out, arc_prefix="ContiTool.app")
        print(f"[build] Created macOS ZIP: {zip_out}")

        if shutil.which("hdiutil"):
            dmg_out = rel_dir / f"ContiTool-v{__version__}-macos-{arch}.dmg"
            subprocess.run(
                [
                    "hdiutil",
                    "create",
                    "-volname",
                    f"ContiTool v{__version__}",
                    "-srcfolder",
                    str(app_bundle),
                    "-ov",
                    "-format",
                    "UDZO",
                    str(dmg_out),
                ],
                check=True,
            )
            print(f"[build] Created macOS DMG: {dmg_out}")

    elif sys_name == "Windows":
        app_folder = dist_dir / "ContiTool"
        if not app_folder.exists():
            raise RuntimeError(f"Expected Windows build folder not found: {app_folder}")
        _copy_legal_files(app_folder)
        zip_out = rel_dir / f"ContiTool-v{__version__}-windows-{arch}.zip"
        _zip_directory(app_folder, zip_out, arc_prefix="ContiTool")
        print(f"[build] Created Windows ZIP: {zip_out}")

    else:
        app_folder = dist_dir / "ContiTool"
        _copy_legal_files(app_folder)
        archive_base = rel_dir / f"ContiTool-v{__version__}-linux-{arch}"
        tar_out = shutil.make_archive(str(archive_base), "gztar", root_dir=dist_dir, base_dir="ContiTool")
        print(f"[build] Created Linux archive: {tar_out}")


def _copy_legal_files(app_folder: Path) -> None:
    """Next to the executable as well, where users look — the copies inside `_internal/` are easy to miss."""
    for name in LEGAL_FILES:
        src = ROOT_DIR / name
        if src.is_dir():
            shutil.copytree(src, app_folder / name, dirs_exist_ok=True)
        else:
            shutil.copy2(src, app_folder / name)


if __name__ == "__main__":
    build()
