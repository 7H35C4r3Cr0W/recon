#!/usr/bin/env bash
# Build a single-file, double-click AppImage of the oscp-recon GUI for Linux / Kali.
#
#   PRODUCES:  dist/oscp-recon-<version>-x86_64.AppImage   (download -> `chmod +x` -> double-click)
#
# WHY AN APPIMAGE: it bundles the existing PySide6 app together with a relocatable standalone
# CPython, so the end user needs no Python, no pip, no apt. Qt AND QtWebEngine (the graph view +
# HackTricks pane) ship *inside* the PySide6 wheel, so they come along automatically. This is
# packaging only — the app itself is unchanged and still makes NO network calls at runtime.
#
# RUN THIS ON KALI (or any recent x86_64 Linux) with a normal user — NOT in CI/headless. It fetches
# the linuxdeploy / appimagetool helpers once at BUILD time; the resulting AppImage needs nothing.
#
# This is a maintainer recipe, not a runtime component. QtWebEngine is the fussy part: if the
# built AppImage's graph / HackTricks panes come up blank on some target, that box is missing the
# Chromium runtime libs — either install linuxdeploy before building (this script will then bundle
# them) or `apt install libnss3 libxcomposite1 libxdamage1 libxrandr2 libasound2` on the target.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$REPO/dist"
BUILD="$REPO/build/appimage"
APPDIR="$BUILD/oscp-recon.AppDir"
PYVER="${OSCPRECON_PYVER:-3.11}"
ARCH="$(uname -m)"

say() { printf '\n\033[1;36m[build-appimage]\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31m[build-appimage] %s\033[0m\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || die "missing '$1' — install it first:  $2"
}

say "prerequisites"
need uv "curl -LsSf https://astral.sh/uv/install.sh | sh"
need appimagetool "apt install appimagetool   (or grab it from github.com/AppImage/appimagetool)"

say "clean workspace"
rm -rf "$BUILD"
mkdir -p "$APPDIR/usr" "$DIST"

say "build the wheel"
uv build --wheel --out-dir "$BUILD/wheel" "$REPO"
WHEEL="$(ls -1 "$BUILD"/wheel/*.whl | head -n1)"
[ -n "$WHEEL" ] || die "wheel build produced no artifact"
VERSION="$(basename "$WHEEL" | sed -E 's/^oscp_recon-([^-]+)-.*/\1/')"

say "stage a relocatable standalone Python $PYVER"
uv python install "$PYVER"
PYBIN="$(uv python find "$PYVER")"
# readlink -f resolves uv's version symlink (cpython-3.11-... -> cpython-3.11.15-...) to the REAL
# directory; copying the symlink itself would bundle a dangling link and pip would write into the
# shared uv store instead of the AppDir. Copy real files so the bundle is self-contained.
PYROOT="$(readlink -f "$(dirname "$(dirname "$PYBIN")")")"
rm -rf "$APPDIR/usr/python"
cp -a "$PYROOT" "$APPDIR/usr/python"
APP_PY="$APPDIR/usr/python/bin/python3"

say "install oscp-recon (+ PySide6 with bundled Qt/QtWebEngine) into the bundle"
# The bundled copy is OURS to modify (not a system/shared Python): drop uv's EXTERNALLY-MANAGED
# marker and install with the copy's own pip, overriding PEP 668. The copy stays relocatable.
find "$APPDIR/usr/python" -name EXTERNALLY-MANAGED -delete 2>/dev/null || true
"$APP_PY" -m ensurepip --upgrade >/dev/null 2>&1 || true
"$APP_PY" -m pip install --break-system-packages --no-warn-script-location "$WHEEL"

say "write AppRun"
cat > "$APPDIR/AppRun" <<'APPRUN'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
# lab boxes often have no GPU/sandbox; keep the same flags the app sets itself, overridable.
export QTWEBENGINE_CHROMIUM_FLAGS="${QTWEBENGINE_CHROMIUM_FLAGS:---no-sandbox --disable-gpu}"
export LD_LIBRARY_PATH="$HERE/usr/lib:${LD_LIBRARY_PATH:-}"
exec "$HERE/usr/python/bin/python3" -m oscprecon "$@"
APPRUN
chmod +x "$APPDIR/AppRun"

say "install desktop entry + icon"
install -Dm644 "$REPO/packaging/oscp-recon.desktop" "$APPDIR/usr/share/applications/oscp-recon.desktop"
install -Dm644 "$REPO/packaging/oscp-recon.png" \
    "$APPDIR/usr/share/icons/hicolor/256x256/apps/oscp-recon.png"
cp "$REPO/packaging/oscp-recon.desktop" "$APPDIR/oscp-recon.desktop"
cp "$REPO/packaging/oscp-recon.png" "$APPDIR/oscp-recon.png"

# Qt AND QtWebEngine ship *inside* the PySide6 wheel we just installed, so they are already in the
# AppDir — no linuxdeploy-plugin-qt needed (that plugin targets system-Qt apps, not PySide6's bundled
# Qt). The only external gap is the handful of SYSTEM libs Chromium dlopen's (libnss3, libxcomposite1,
# libxdamage1, libxrandr2, libasound2). Those are present on Kali and any desktop Linux, so the graph
# and HackTricks panes work out of the box there; on a stripped target, apt-install those five. To
# bundle them for maximal portability, run `linuxdeploy --appdir <AppDir> -e <python>` before packing.

say "pack the AppImage"
OUT="$DIST/oscp-recon-${VERSION}-${ARCH}.AppImage"
ARCH="$ARCH" appimagetool "$APPDIR" "$OUT"

say "done -> $OUT"
say "smoke test it:  chmod +x '$OUT' && '$OUT'"
