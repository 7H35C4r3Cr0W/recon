#!/usr/bin/env bash
# Bootstrap oscp-recon on a fresh Kali/Debian host: the wrapped recon tools + uv + the app itself.
#
#   curl -LsSf … | bash        # NO — always read a script before piping it to a shell
#   git clone <repo> && cd oscp-recon && ./install.sh
#
# Idempotent and fail-safe: re-running is harmless, any step failing aborts loudly rather than
# leaving a half-set-up host. It installs ONLY the §2-allow-listed recon tools; the opt-in Spray-mode
# tools (hydra/medusa) are installed only with --with-spray. Nothing here needs the internet at the
# app's RUNTIME — this is one-time setup.
set -euo pipefail
# why: a bootstrap the user explicitly ran must never block on an interactive apt prompt — especially
# one that would be invisible because we suppress apt's chatter below.
export DEBIAN_FRONTEND=noninteractive

WITH_SPRAY=0
for arg in "$@"; do
    case "$arg" in
        --with-spray) WITH_SPRAY=1 ;;
        -y | --yes) : ;;  # accepted for back-compat; this bootstrap is always non-interactive
        -h | --help)
            tail -n +2 "$0" | grep '^#' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            printf 'unknown option: %s (try --help)\n' "$arg" >&2
            exit 2
            ;;
    esac
done

REPO="$(cd "$(dirname "$0")" && pwd)"
say() { printf '\n\033[1;36m[install]\033[0m %s\n' "$*"; }
die() {
    printf '\n\033[1;31m[install] %s\033[0m\n' "$*" >&2
    exit 1
}

# ---- prerequisites -----------------------------------------------------------------------------
command -v apt-get >/dev/null 2>&1 ||
    die "this bootstrap targets Debian/Kali (needs apt-get). On another OS, install the tools from CLAUDE.md §4 by hand, then run 'uv sync'."

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    die "not root and no sudo — re-run as root or install sudo first."
fi

# ---- system recon tools (§2 allow-list; CLAUDE.md §4) -------------------------------------------
CORE_PKGS=(
    nmap feroxbuster gobuster ffuf dirsearch nikto whatweb wpscan curl wget
    smbclient smbmap enum4linux-ng rpcclient impacket-scripts netexec
    ldap-utils snmp onesixtyone dnsrecon dnsutils ike-scan nbtscan
    ntpsec-ntpdate seclists exploitdb redis-tools
)
SPRAY_PKGS=(hydra medusa)

say "apt update"
$SUDO apt-get update

say "install the recon tool set (${#CORE_PKGS[@]} packages — this can take a few minutes on a fresh host)"
# install core packages one-by-one so a single unavailable/renamed package can't abort the rest, and
# print a per-package result so the run never looks frozen while apt works.
FAILED=()
for pkg in "${CORE_PKGS[@]}"; do
    printf '  • %-22s ' "$pkg"
    if $SUDO apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1; then
        printf 'ok\n'
    else
        printf 'skip (unavailable/renamed on this release)\n'
        FAILED+=("$pkg")
    fi
done
[ "${#FAILED[@]}" -gt 0 ] && say "note: could not install: ${FAILED[*]} — install by hand if you need them"

if [ "$WITH_SPRAY" -eq 1 ]; then
    say "install opt-in Spray-mode tools (hydra/medusa) — you asked with --with-spray"
    for pkg in "${SPRAY_PKGS[@]}"; do
        printf '  • %-22s ' "$pkg"
        if $SUDO apt-get install -y "$pkg" >/dev/null 2>&1; then printf 'ok\n'; else printf 'skip\n'; fi
    done
fi

# ---- uv + the app ------------------------------------------------------------------------------
if ! command -v uv >/dev/null 2>&1; then
    say "install uv (Python dependency manager)"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi
command -v uv >/dev/null 2>&1 || die "uv is still not on PATH — add ~/.local/bin to PATH and re-run."

say "sync the project (creates .venv, installs Nabu)"
(cd "$REPO" && uv sync)

# ---- put nabu / nabu-cli on PATH ---------------------------------------------------------------
# why: uv sync installs the console scripts into $REPO/.venv/bin, which is NOT on PATH — so a bare
# `nabu` / `nabu-cli` would say "command not found". Symlink them into ~/.local/bin (on Kali's PATH).
say "link nabu / nabu-cli onto your PATH (~/.local/bin)"
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
for name in nabu nabu-cli; do
    if [ -x "$REPO/.venv/bin/$name" ]; then
        ln -sfn "$REPO/.venv/bin/$name" "$BIN_DIR/$name"
        printf '  • %-9s -> %s\n' "$name" "$BIN_DIR/$name"
    fi
done
case ":$PATH:" in
    *":$BIN_DIR:"*) ON_PATH=1 ;;
    *) ON_PATH=0 ;;
esac

# ---- readiness check ---------------------------------------------------------------------------
say "checking host readiness (doctor)"
(cd "$REPO" && uv run nabu-cli doctor) || true  # report only; a missing tool is not fatal

if [ "$ON_PATH" -eq 1 ]; then
    say "done. Next:
  nabu-cli doctor       # re-check the wrapped tools any time
  nabu                  # launch the GUI
Spray mode stays OFF by default; enable it in Preferences → Scan (§2a)."
else
    say "done — but ~/.local/bin is not on your PATH yet. Add it and reload your shell:
  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc   # (or ~/.bashrc)
  exec \$SHELL
Then run:  nabu-cli doctor   and   nabu
Or skip PATH entirely:  cd '$REPO' && uv run nabu"
fi
