#!/usr/bin/env bash
# Remove what install-desktop.sh created (launchers, Desktop icons, hicolor icons, PATH symlinks).
set -euo pipefail

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
APPS_DIR="$DATA_HOME/applications"
ICONS_DIR="$DATA_HOME/icons/hicolor"
BIN_DIR="$HOME/.local/bin"
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"

rm -f "$APPS_DIR/nabu.desktop" "$APPS_DIR/nabu-cli.desktop"
rm -f "$DESKTOP_DIR/nabu.desktop" "$DESKTOP_DIR/nabu-cli.desktop"
for size in 16 32 48 64 128 256 512; do
  rm -f "$ICONS_DIR/${size}x${size}/apps/nabu.png"
done
# only remove the symlinks we created (never a real binary)
for name in nabu nabu-cli; do
  [ -L "$BIN_DIR/$name" ] && rm -f "$BIN_DIR/$name"
done

update-desktop-database "$APPS_DIR" 2>/dev/null || true
gtk-update-icon-cache -f -t "$ICONS_DIR" 2>/dev/null || true
echo "==> Nabu desktop integration removed."
