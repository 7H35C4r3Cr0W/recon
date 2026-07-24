#!/usr/bin/env bash
# Install Nabu into the local desktop: a taskbar/menu launcher for the GUI, a terminal launcher for
# the headless CLI, a Desktop icon, hicolor icons, and PATH symlinks. Idempotent — safe to re-run.
# No root required; everything lands under $HOME (XDG user dirs). Reverse with uninstall-desktop.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="$REPO_ROOT/packaging"

# why: prefer the repo venv's console scripts (absolute path → works no matter the session PATH);
# fall back to whatever `nabu`/`nabu-cli` resolve to on PATH (e.g. a pipx/global install).
GUI_BIN="$REPO_ROOT/.venv/bin/nabu"
CLI_BIN="$REPO_ROOT/.venv/bin/nabu-cli"
[ -x "$GUI_BIN" ] || GUI_BIN="$(command -v nabu || true)"
[ -x "$CLI_BIN" ] || CLI_BIN="$(command -v nabu-cli || true)"
if [ -z "$GUI_BIN" ] || [ -z "$CLI_BIN" ]; then
  echo "!! Could not find nabu / nabu-cli. Run 'uv sync' in $REPO_ROOT first." >&2
  exit 1
fi

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
APPS_DIR="$DATA_HOME/applications"
ICONS_DIR="$DATA_HOME/icons/hicolor"
BIN_DIR="$HOME/.local/bin"
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"

mkdir -p "$APPS_DIR" "$BIN_DIR" "$DESKTOP_DIR"

echo "==> Nabu desktop install"
echo "    repo:     $REPO_ROOT"
echo "    gui bin:  $GUI_BIN"
echo "    cli bin:  $CLI_BIN"

# --- PATH symlinks so `nabu` / `nabu-cli` work from any terminal --------------------------------
for pair in "nabu:$GUI_BIN" "nabu-cli:$CLI_BIN"; do
  name="${pair%%:*}"; target="${pair#*:}"
  link="$BIN_DIR/$name"
  # never point the link at itself: without a repo venv, `command -v nabu` resolves to THIS link,
  # and `ln -sfn` would then create a self-referential (broken) symlink and delete the working one.
  if [ "$(readlink -f "$target" 2>/dev/null || echo "$target")" = "$(readlink -f "$link" 2>/dev/null || echo "$link")" ] \
     && [ -L "$link" ]; then
    echo "    kept:     $link (already points at $(readlink "$link"))"
    continue
  fi
  ln -sfn "$target" "$link"
  echo "    linked:   $link -> $target"
done

# --- hicolor icons (Icon=nabu resolves via the icon theme) --------------------------------------
for size in 16 32 48 64 128 256 512; do
  src="$PKG/icons/nabu-${size}.png"
  [ -f "$src" ] || continue
  dst="$ICONS_DIR/${size}x${size}/apps"
  mkdir -p "$dst"
  install -m 0644 "$src" "$dst/nabu.png"
done
echo "    icons:    installed into $ICONS_DIR"

# --- GUI launcher (taskbar / app menu / Desktop) ------------------------------------------------
# Absolute Exec so a double-click works regardless of the session PATH. A right-click Action opens
# the headless CLI in a terminal.
GUI_DESKTOP="$APPS_DIR/nabu.desktop"
cat > "$GUI_DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=Nabu
GenericName=Recon Workspace
Comment=Recon-first, OSCP exam-legal enumeration workspace
Exec=$GUI_BIN
Icon=nabu
Terminal=false
Categories=Network;Security;
Keywords=nabu;oscp;recon;enumeration;nmap;pentest;security;
StartupNotify=true
StartupWMClass=nabu
Actions=cli;

[Desktop Action cli]
Name=Open Nabu CLI (headless)
Exec=bash -c "$CLI_BIN --help; exec bash -i"
EOF

# --- CLI launcher (its own menu entry; Terminal=true → wrapped in the preferred terminal) --------
CLI_DESKTOP="$APPS_DIR/nabu-cli.desktop"
cat > "$CLI_DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=Nabu CLI
GenericName=Headless Recon CLI
Comment=Nabu headless recon CLI (recon-only, OSCP exam-legal)
Exec=bash -c "$CLI_BIN --help; exec bash -i"
Icon=nabu
Terminal=true
Categories=Network;Security;ConsoleOnly;
Keywords=nabu;oscp;recon;cli;nmap;pentest;
StartupNotify=false
EOF

# --- Desktop icons (copy + mark trusted/executable so the DE launches them without a prompt) -----
# Two DIFFERENT trust mechanisms — set both so the launcher is trusted whether the box runs XFCE
# (Kali default) or GNOME:
#   * XFCE / xfdesktop 4.16+ trusts a launcher only when metadata::xfce-exe-checksum equals the
#     file's SHA-256 (this is what clicking "Launch Anyway" stores). metadata::trusted is IGNORED by
#     XFCE, so without the checksum xfdesktop shows "Untrusted application launcher" on EVERY click.
#   * GNOME / Nautilus uses metadata::trusted=true.
# The checksum is content-only, so compute it AFTER the copy (chmod does not change file content).
for d in "$GUI_DESKTOP" "$CLI_DESKTOP"; do
  cp -f "$d" "$DESKTOP_DIR/"
  base="$DESKTOP_DIR/$(basename "$d")"
  chmod +x "$base"
  sum="$(sha256sum "$base" | cut -d' ' -f1)"
  gio set -t string "$base" metadata::xfce-exe-checksum "$sum" 2>/dev/null || true  # XFCE
  gio set "$base" metadata::trusted true 2>/dev/null || true                        # GNOME/Nautilus
done
echo "    desktop:  launchers copied to $DESKTOP_DIR (marked trusted for XFCE + GNOME)"

# --- refresh caches -----------------------------------------------------------------------------
update-desktop-database "$APPS_DIR" 2>/dev/null || true
gtk-update-icon-cache -f -t "$ICONS_DIR" 2>/dev/null || true
command -v xdg-desktop-menu >/dev/null 2>&1 && xdg-desktop-menu forceupdate 2>/dev/null || true

echo "==> Done. Find 'Nabu' (GUI) and 'Nabu CLI' in the applications menu, taskbar, and Desktop."
echo "    'nabu' and 'nabu-cli' are now on your PATH (via $BIN_DIR)."
