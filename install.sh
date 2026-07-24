#!/usr/bin/env bash
# Bootstrap oscp-recon on a fresh Kali/Debian host: the wrapped recon tools + uv + the app itself.
#
#   curl -LsSf … | bash        # NO — always read a script before piping it to a shell
#   git clone <repo> && cd oscp-recon && ./install.sh        (run ./install.sh --help for details)
#
# Idempotent and fail-safe: re-running is harmless, any step failing aborts loudly rather than
# leaving a half-set-up host. It installs ONLY the §2-allow-listed recon tools; the opt-in Spray-mode
# tools (hydra/medusa) are installed only with --with-spray. Nothing here needs the internet at the
# app's RUNTIME — this is one-time setup.
set -euo pipefail
# why: a bootstrap the user explicitly ran must never block on an interactive apt prompt — especially
# one that would be invisible because we suppress apt's chatter below.
export DEBIAN_FRONTEND=noninteractive

# ---- colours (only on a real terminal; kept out of pipes/CI logs) -------------------------------
if [ -t 1 ]; then
    IS_TTY=1
    B=$'\033[1m'
    DIM=$'\033[2m'
    R=$'\033[0m'
    CY=$'\033[1;36m'
    GRN=$'\033[1;32m'
    YEL=$'\033[1;33m'
    RED=$'\033[1;31m'
else
    IS_TTY=0
    B='' DIM='' R='' CY='' GRN='' YEL='' RED=''
fi

usage() {
    cat <<EOF
${B}Nabu installer${R} — set up the Local Recon Workspace on Kali/Debian.

${B}USAGE${R}
  ./install.sh [options]

${B}WHAT IT DOES${R}  ${DIM}(about 3–8 min on a fresh host, mostly downloads)${R}
  1. apt update
  2. install the wrapped recon tools (nmap, feroxbuster, smbclient, netexec, …)
  3. install uv (the Python package manager) if it is missing
  4. set up Nabu in an isolated virtualenv (uv sync)
  5. put 'nabu' and 'nabu-cli' on your PATH (~/.local/bin)
  6. run a health check (nabu-cli doctor)

${B}OPTIONS${R}
  --with-spray   also install the opt-in Spray-mode tools (hydra, medusa).
                 Spray stays OFF by default in the app; this only installs them.
  -y, --yes      accepted for compatibility — the installer is always
                 non-interactive and never stops to ask.
  -h, --help     show this help and exit.

${B}GOOD TO KNOW${R}
  • Safe to re-run — every step is idempotent.
  • apt needs root, so you may be asked for your sudo password once near the start.
  • A live progress bar shows each tool installing; big packages (seclists,
    exploitdb) take a while — the spinner means it is working, not frozen.
  • Nothing here runs at the app's runtime; this is one-time setup and stays offline.
  • On another OS, install the tools from CLAUDE.md §4 by hand, then run 'uv sync'.

${B}EXAMPLES${R}
  ./install.sh                 # standard install
  ./install.sh --with-spray    # also install hydra/medusa
  ./install.sh --help          # this screen

After it finishes:  ${B}nabu-cli doctor${R}   then   ${B}nabu${R}
EOF
}

# ---- argument parsing --------------------------------------------------------------------------
WITH_SPRAY=0
for arg in "$@"; do
    case "$arg" in
        --with-spray) WITH_SPRAY=1 ;;
        -y | --yes) : ;;  # accepted for back-compat; this bootstrap is always non-interactive
        -h | --help)
            usage
            exit 0
            ;;
        *)
            printf '%sunknown option: %s%s (try --help)\n' "$RED" "$arg" "$R" >&2
            exit 2
            ;;
    esac
done

REPO="$(cd "$(dirname "$0")" && pwd)"

# ---- messaging + progress helpers --------------------------------------------------------------
say() { printf '%s  %s%s\n' "$DIM" "$*" "$R"; }
step() {
    STEP=$((STEP + 1))
    printf '\n%s[%d/%d]%s %s%s%s\n' "$CY" "$STEP" "$TOTAL_STEPS" "$R" "$B" "$*" "$R"
}
warn() { printf '%s  ! %s%s\n' "$YEL" "$*" "$R"; }
die() {
    printf '\n%s[install] %s%s\n' "$RED" "$*" "$R" >&2
    exit 1
}
STEP=0
TOTAL_STEPS=0

_rep() { # _rep <n> <char> → the char repeated n times (multibyte-safe)
    local n=$1 s=$2 o=''
    while [ "$n" -gt 0 ]; do
        o="$o$s"
        n=$((n - 1))
    done
    printf '%s' "$o"
}
_bar() { # _bar <done> <total> → "[████░░░░░░]  40%"
    local cur=$1 total=$2 width=22 filled empty pct
    [ "$total" -gt 0 ] || total=1
    [ "$cur" -gt "$total" ] && cur=$total
    filled=$((cur * width / total))
    empty=$((width - filled))
    pct=$((cur * 100 / total))
    printf '[%s%s] %3d%%' "$(_rep "$filled" '█')" "$(_rep "$empty" '░')" "$pct"
}
apt_one() { # apt_one <pkg> <done-before> <total> → install one package, animating; returns apt's rc
    local pkg=$1 done=$2 total=$3 rc
    if [ "$IS_TTY" -eq 1 ]; then
        local sp='|/-\' k=0 pid
        printf '\r  %s  %-44s' "$(_bar "$done" "$total")" "installing $pkg ($((done + 1))/$total)"
        $SUDO apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1 &
        pid=$!
        while kill -0 "$pid" 2>/dev/null; do
            printf '\r  %s  %-44s' "$(_bar "$done" "$total")" "installing $pkg ($((done + 1))/$total) ${sp:$((k % 4)):1}"
            k=$((k + 1))
            sleep 0.2
        done
        if wait "$pid"; then rc=0; else rc=$?; fi
    else
        printf '  [%2d/%2d] %-22s ... ' "$((done + 1))" "$total" "$pkg"
        if $SUDO apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1; then
            rc=0
            printf 'ok\n'
        else
            rc=1
            printf 'skip\n'
        fi
    fi
    return "$rc"
}
apt_group() { # apt_group <label> <pkg...> → install a list with a live bar; appends misses to FAILED
    local label=$1
    shift
    local pkgs=("$@") total=${#pkgs[@]} i=0 miss=0 pkg okc
    for pkg in "${pkgs[@]}"; do
        if apt_one "$pkg" "$i" "$total"; then
            :
        else
            FAILED+=("$pkg")
            miss=$((miss + 1))
        fi
        i=$((i + 1))
    done
    okc=$((total - miss))
    if [ "$IS_TTY" -eq 1 ]; then
        printf '\r  %s  %s✔%s %-42s\n' "$(_bar "$total" "$total")" "$GRN" "$R" "$label ($okc/$total)"
    else
        printf '  ✔ %s (%d/%d)\n' "$label" "$okc" "$total"
    fi
    return 0 # why: never let this function's exit status abort the script under set -e
}

# a friendly message instead of a bare abort if something unexpected fails
trap 'printf "\n%s[install] something failed unexpectedly (line %s).%s\n%sIt is safe to re-run: ./install.sh%s\n" "$RED" "$LINENO" "$R" "$DIM" "$R" >&2' ERR

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

# total phases up front so the [N/T] counter is honest (uv-install + spray are conditional)
NEED_UV=0
command -v uv >/dev/null 2>&1 || NEED_UV=1
TOTAL_STEPS=$((5 + WITH_SPRAY + NEED_UV)) # apt-update, tools, [spray], [uv], sync, link, doctor
FAILED=()

# ---- welcome + plan ----------------------------------------------------------------------------
printf '\n%s%s   {o,o}   Nabu — Local Recon Workspace%s\n' "$CY" "$B" "$R"
printf '%s   |)__)  installer · recon-first · OSCP exam-legal · offline%s\n' "$DIM" "$R"
printf '%s   -"-"-%s\n' "$DIM" "$R"

printf '\n%sHere is the plan (%s steps, ~3–8 min — mostly downloads):%s\n' "$B" "$TOTAL_STEPS" "$R"
printf '   1. update apt package lists\n'
printf '   2. install %s recon tools (nmap, feroxbuster, smbclient, netexec, …)\n' "${#CORE_PKGS[@]}"
[ "$WITH_SPRAY" -eq 1 ] && printf '   +  install spray tools (hydra, medusa)\n'
[ "$NEED_UV" -eq 1 ] && printf '   +  install uv (Python package manager)\n'
printf '   3. set up Nabu in its own virtualenv\n'
printf '   4. put nabu / nabu-cli on your PATH\n'
printf '   5. run a health check\n'
printf '%s   safe to re-run · Ctrl-C to abort · run ./install.sh --help for details%s\n' "$DIM" "$R"

if [ -n "$SUDO" ]; then
    printf '\n%s   ▸ apt needs root — you may be prompted for your %s password once.%s\n' "$YEL" "$(id -un)" "$R"
fi

# ---- run ---------------------------------------------------------------------------------------
step "apt update"
$SUDO apt-get update

step "install the recon tool set — ${#CORE_PKGS[@]} packages"
say "the bar advances as each finishes; the spinner shows the current one downloading."
apt_group "recon tools installed" "${CORE_PKGS[@]}"
[ "${#FAILED[@]}" -gt 0 ] && warn "could not install: ${FAILED[*]} — renamed/removed on this release; install by hand if you need them"

if [ "$WITH_SPRAY" -eq 1 ]; then
    step "install opt-in Spray-mode tools (hydra/medusa)"
    say "you asked with --with-spray. Spray mode still ships OFF in the app (§2a)."
    apt_group "spray tools installed" "${SPRAY_PKGS[@]}"
fi

if [ "$NEED_UV" -eq 1 ]; then
    step "install uv (Python dependency manager)"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi
command -v uv >/dev/null 2>&1 || die "uv is still not on PATH — add ~/.local/bin to PATH and re-run."

step "set up Nabu (create the virtualenv, install dependencies)"
say "resolving Python packages — this is quick, uv streams its progress below."
(cd "$REPO" && uv sync)

# why: uv sync installs the console scripts into $REPO/.venv/bin, which is NOT on PATH — so a bare
# `nabu` / `nabu-cli` would say "command not found". Symlink them into ~/.local/bin (on Kali's PATH).
step "put nabu / nabu-cli on your PATH (~/.local/bin)"
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
for name in nabu nabu-cli; do
    if [ -x "$REPO/.venv/bin/$name" ]; then
        ln -sfn "$REPO/.venv/bin/$name" "$BIN_DIR/$name"
        printf '  %s•%s %-9s -> %s\n' "$GRN" "$R" "$name" "$BIN_DIR/$name"
    fi
done
case ":$PATH:" in
    *":$BIN_DIR:"*) ON_PATH=1 ;;
    *) ON_PATH=0 ;;
esac

step "check the host is ready (doctor)"
(cd "$REPO" && uv run nabu-cli doctor) || true # report only; a missing tool is not fatal

# ---- done --------------------------------------------------------------------------------------
trap - ERR
printf '\n%s   ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄%s\n' "$GRN" "$R"
printf '%s   ✔ Setup complete — Nabu is installed.%s  %s(%ss)%s\n' "$GRN$B" "$R" "$DIM" "$SECONDS" "$R"
if [ "${#FAILED[@]}" -gt 0 ]; then
    warn "${#FAILED[@]} tool(s) skipped: ${FAILED[*]} — Nabu still runs; 'nabu-cli doctor' shows install hints."
fi
if [ "$ON_PATH" -eq 1 ]; then
    printf '\n%s   Launch it:%s\n' "$B" "$R"
    printf '     %snabu%s              # the GUI\n' "$B" "$R"
    printf '     %snabu-cli doctor%s   # re-check the wrapped tools any time\n' "$B" "$R"
    printf '%s   Spray mode stays OFF by default; enable it in Preferences → Scan (§2a).%s\n' "$DIM" "$R"
else
    printf '\n%s   Almost there — ~/.local/bin is not on your PATH yet.%s\n' "$YEL" "$R"
    printf '   Add it, then open a new terminal:\n'
    printf "     echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc   # (or ~/.bashrc)\n"
    printf '     exec $SHELL\n'
    printf '   Then:  %snabu-cli doctor%s   and   %snabu%s\n' "$B" "$R" "$B" "$R"
    printf '%s   Or skip PATH entirely:  cd %s && uv run nabu%s\n' "$DIM" "$REPO" "$R"
fi
printf '\n'
