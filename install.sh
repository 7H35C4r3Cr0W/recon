#!/usr/bin/env bash
# Bootstrap oscp-recon on a fresh Kali/Debian host: the wrapped recon tools + uv + the app itself.
#
#   curl -LsSf … | bash        # NO — always read a script before piping it to a shell
#   git clone <repo> && cd oscp-recon && ./install.sh        (run ./install.sh --help for details)
#
# SAFE ACROSS KALI VERSIONS. The Python side is fully venv-isolated (uv sync) and can never touch the
# system. The only step that touches the host is the apt tool-install, and it is deliberately
# conservative so it CANNOT break a rolling-release box:
#   • installs ONLY the tools you are actually missing — already-present tools are never upgraded,
#     so it never triggers a partial upgrade of a rolling release (the classic "broke apt + libraries").
#   • resolves every package name against what actually exists on THIS release (package names drift
#     across Kali versions: dnsutils→bind9-dnsutils, ntpdate→ntpsec-ntpdate, crackmapexec→netexec);
#     a name that isn't available is skipped, never fatal.
#   • DRY-RUNS the plan first and REFUSES to proceed if apt would remove or downgrade anything.
#   • installs the remainder in ONE transaction with visible output, and heals dpkg on Ctrl-C — so an
#     interrupted run never leaves apt/dpkg half-configured.
# It installs ONLY the §2-allow-listed recon tools; the opt-in Spray-mode tools (hydra/medusa) are
# installed only with --with-spray. Nothing here needs the internet at the app's RUNTIME.
set -euo pipefail
# why: a bootstrap the user explicitly ran must never block on an interactive apt prompt.
export DEBIAN_FRONTEND=noninteractive

# ---- colours (only on a real terminal; kept out of pipes/CI logs) -------------------------------
if [ -t 1 ]; then
    B=$'\033[1m'
    DIM=$'\033[2m'
    R=$'\033[0m'
    CY=$'\033[1;36m'
    GRN=$'\033[1;32m'
    YEL=$'\033[1;33m'
    RED=$'\033[1;31m'
else
    B='' DIM='' R='' CY='' GRN='' YEL='' RED=''
fi

usage() {
    cat <<EOF
${B}Nabu installer${R} — set up the Local Recon Workspace on Kali/Debian.

${B}USAGE${R}
  ./install.sh [options]

${B}WHAT IT DOES${R}  ${DIM}(about 3–8 min on a fresh host, mostly downloads)${R}
  1. apt update
  2. install ONLY the recon tools you are missing (nmap, feroxbuster, netexec, …),
     in one transaction, after a dry-run that aborts if apt would remove anything
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

${B}WHY IT WON'T BREAK YOUR KALI${R}
  • It only installs tools you don't already have — it never force-upgrades an
    installed package, so it can't drag your rolling release into a partial upgrade.
  • It dry-runs the plan first and REFUSES to continue if apt would remove or
    downgrade anything (it tells you to run 'sudo apt full-upgrade' instead).
  • Package names are resolved to what exists on your Kali version, so a renamed
    package is skipped — never a hard failure.
  • If you Ctrl-C mid-apt, it heals dpkg so your system is never left broken.
  • The Python app lives in its own virtualenv; that step can't touch the system.

${B}GOOD TO KNOW${R}
  • Safe to re-run — every step is idempotent.
  • apt needs root, so you may be asked for your sudo password once near the start.
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

# ---- messaging helpers -------------------------------------------------------------------------
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

# ---- interrupt / failure messaging -------------------------------------------------------------
# We deliberately do NOT run sudo repair work at abort time — firing `dpkg --configure -a` the moment
# you hit Ctrl-C would surprise you with a password prompt exactly when you want out. Instead: apt's
# own DPkg::ConfigurePending finishes a partially-unpacked package on the next apt run, and this
# script repairs any pre-existing half-configured dpkg at STARTUP (see below) — so a plain re-run
# genuinely self-heals, which is the promise we make.
trap 'printf "\n%s[install] aborted. If that interrupted an apt install, just re-run ./install.sh —\n          it repairs dpkg at startup and continues cleanly.%s\n" "$YEL" "$R" >&2; exit 130' INT TERM
trap 'printf "\n%s[install] something failed unexpectedly (line %s).%s\n%sSafe to re-run: ./install.sh — it repairs dpkg and skips what is already done.%s\n" "$RED" "$LINENO" "$R" "$DIM" "$R" >&2' ERR

# ---- apt helpers -------------------------------------------------------------------------------
pkg_available() { # is <pkg> installable on THIS release?
    local cand
    cand="$(apt-cache policy "$1" 2>/dev/null | awk -F': ' '/Candidate:/{print $2}')"
    [ -n "$cand" ] && [ "$cand" != "(none)" ]
}
pkg_installed() { # is <pkg> already installed (at any version)?
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}
# A "spec" is one tool as pipe-separated aliases, tried left→right (modern name first, older fallback
# second) — e.g. "bind9-dnsutils|dnsutils". group_installed skips the whole group if ANY alias is
# already present (so we never reinstall dig just because it moved packages); resolve_spec picks the
# first alias that is installable on this release.
group_installed() {
    local spec=$1 a _aliases
    IFS='|' read -ra _aliases <<<"$spec"
    for a in "${_aliases[@]}"; do pkg_installed "$a" && return 0; done
    return 1
}
resolve_spec() {
    local spec=$1 a _aliases
    IFS='|' read -ra _aliases <<<"$spec"
    for a in "${_aliases[@]}"; do
        if pkg_available "$a"; then
            printf '%s' "$a"
            return 0
        fi
    done
    return 1
}

# install_missing <step-label> <spec...> — the whole safe path: resolve names, drop already-installed
# tools, dry-run-and-refuse-removals, then install the remainder in ONE visible transaction.
install_missing() {
    local label=$1
    shift
    local specs=("$@") spec pkg
    local to_install=() unresolved=()

    for spec in "${specs[@]}"; do
        if group_installed "$spec"; then
            continue # already have it — never force an upgrade (that is what breaks rolling Kali)
        fi
        if pkg="$(resolve_spec "$spec")"; then
            to_install+=("$pkg")
        else
            unresolved+=("${spec//|/ or }")
        fi
    done

    if [ "${#unresolved[@]}" -gt 0 ]; then
        warn "not available on this Kali release, skipping: ${unresolved[*]}"
    fi

    if [ "${#to_install[@]}" -eq 0 ]; then
        say "all $label already present — nothing to install, no upgrades forced. ✔"
        return 0
    fi

    say "missing: ${to_install[*]}"

    # low-disk heads-up before the large data sets (seclists/exploitdb are ~1GB together)
    local free_mb
    free_mb="$(df -Pm "$REPO" 2>/dev/null | awk 'NR==2{print $4}')"
    if [ -n "${free_mb:-}" ] && [ "$free_mb" -lt 2048 ] &&
        printf '%s\n' "${to_install[@]}" | grep -qE '^(seclists|exploitdb)$'; then
        warn "only ${free_mb}MB free and seclists/exploitdb are large — free some space if apt aborts."
    fi

    # DRY RUN (no root needed): refuse to touch the system if apt would REMOVE or DOWNGRADE anything.
    local plan rmcount removed
    if ! plan="$(apt-get install -s --no-install-recommends "${to_install[@]}" 2>&1)"; then
        warn "apt could not compute a safe install plan for these tools — skipping to protect your"
        warn "system. Install them yourself when convenient: sudo apt install ${to_install[*]}"
        printf '%s\n' "$plan" | tail -4 | sed 's/^/    /'
        return 0
    fi
    rmcount="$(printf '%s\n' "$plan" | grep -oE '[0-9]+ to remove' | grep -oE '[0-9]+' | head -1 || true)"
    if [ "${rmcount:-0}" -gt 0 ] || printf '%s\n' "$plan" | grep -q 'will be DOWNGRADED'; then
        removed="$(printf '%s\n' "$plan" | awk '/^Remv /{printf "%s ", $2}')"
        warn "SKIPPING the tool install — apt wants to REMOVE/DOWNGRADE packages to do it:"
        [ -n "$removed" ] && warn "  would remove: $removed"
        warn "  That usually means your system needs a full upgrade first. Run:"
        warn "      sudo apt update && sudo apt full-upgrade"
        warn "  then re-run ./install.sh. Nabu's own setup below is unaffected and continues."
        return 0
    fi

    # Safe plan (install + necessary deps only). Do it in ONE transaction, visibly, healing on Ctrl-C.
    say "installing ${#to_install[@]} package(s) in one transaction (apt output follows)…"
    if $SUDO apt-get install -y --no-install-recommends "${to_install[@]}"; then
        printf '  %s✔%s %s installed (%d package(s)).\n' "$GRN" "$R" "$label" "${#to_install[@]}"
    else
        warn "apt did not install everything cleanly — Nabu still runs; 'nabu-cli doctor' lists any"
        warn "remaining gaps and 'nabu-cli doctor --install' can retry them one at a time."
    fi
    return 0
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

# ---- recon tool specs (§2 allow-list; CLAUDE.md §4) --------------------------------------------
# One entry per tool. Aliases (a|b) are tried in order so the right package is picked on every Kali
# release. Intentionally NOT here: 'rpcclient' (its binary ships inside 'smbclient', already listed),
# and the 'ntpsec' package that provides 'ntpq' — ntpsec Conflicts with 'time-daemon'
# (systemd-timesyncd), so auto-installing it would swap the host's time daemon; the ntp module's ntpq
# is therefore left to a deliberate 'nabu-cli doctor --install' rather than force-swapped here.
CORE_SPECS=(
    nmap feroxbuster gobuster ffuf dirsearch nikto whatweb wpscan curl wget
    smbclient smbmap "enum4linux-ng|enum4linux" impacket-scripts
    "netexec|crackmapexec"
    ldap-utils snmp onesixtyone dnsrecon
    "bind9-dnsutils|dnsutils"
    ike-scan nbtscan
    "ntpsec-ntpdate|ntpdate"
    seclists exploitdb redis-tools
)
SPRAY_SPECS=(hydra medusa)

NEED_UV=0
command -v uv >/dev/null 2>&1 || NEED_UV=1
TOTAL_STEPS=$((5 + WITH_SPRAY + NEED_UV)) # apt-update, tools, [spray], [uv], sync, link, doctor

# ---- welcome + plan ----------------------------------------------------------------------------
printf '\n%s%s   {o,o}   Nabu — Local Recon Workspace%s\n' "$CY" "$B" "$R"
printf '%s   |)__)  installer · recon-first · OSCP exam-legal · offline%s\n' "$DIM" "$R"
printf '%s   -"-"-%s\n' "$DIM" "$R"

printf '\n%sHere is the plan (%s steps, ~3–8 min — mostly downloads):%s\n' "$B" "$TOTAL_STEPS" "$R"
printf '   1. update apt package lists\n'
printf '   2. install any MISSING recon tools (already-present ones are left untouched)\n'
[ "$WITH_SPRAY" -eq 1 ] && printf '   +  install spray tools (hydra, medusa)\n'
[ "$NEED_UV" -eq 1 ] && printf '   +  install uv (Python package manager)\n'
printf '   3. set up Nabu in its own virtualenv\n'
printf '   4. put nabu / nabu-cli on your PATH\n'
printf '   5. run a health check\n'
printf '%s   safe to re-run · Ctrl-C to abort (dpkg is healed if it happens mid-apt)%s\n' "$DIM" "$R"

if [ -n "$SUDO" ]; then
    printf '\n%s   ▸ apt needs root — you may be prompted for your %s password once.%s\n' "$YEL" "$(id -un)" "$R"
fi

# ---- run ---------------------------------------------------------------------------------------
# self-heal: repair any pre-existing half-configured dpkg (e.g. from a prior interrupted apt) BEFORE
# we touch apt, so a re-run truly starts clean and the "safe to re-run" promise holds. `dpkg --audit`
# is read-only; the repair only runs when it reports a problem (normally a no-op).
if [ -n "$(dpkg --audit 2>/dev/null)" ]; then
    warn "dpkg looks half-configured (a prior interrupted apt?) — repairing before we start…"
    $SUDO dpkg --configure -a || true
    $SUDO apt-get -f install -y || true
fi

step "apt update"
$SUDO apt-get update ||
    warn "apt update reported problems (stale/expired mirror?) — continuing with the cached indexes."

# A rolling release with many pending upgrades is where "install one thing" turns into a partial
# upgrade. We already sidestep that (only missing tools are installed, and any removal/downgrade is
# refused below) — but flag it so the user can full-upgrade on their own schedule.
held="$(apt-get -s upgrade 2>/dev/null | grep -cE '^Inst ' || true)"
if [ "${held:-0}" -gt 30 ]; then
    warn "your system has ${held} pending package upgrades — Nabu installs only what's missing and"
    warn "will not partial-upgrade you, but consider 'sudo apt full-upgrade' soon to stay consistent."
fi

step "install any missing recon tools"
install_missing "recon tools" "${CORE_SPECS[@]}"

if [ "$WITH_SPRAY" -eq 1 ]; then
    step "install opt-in Spray-mode tools (hydra/medusa)"
    say "you asked with --with-spray. Spray mode still ships OFF in the app (§2a)."
    install_missing "spray tools" "${SPRAY_SPECS[@]}"
fi

if [ "$NEED_UV" -eq 1 ]; then
    step "install uv (Python dependency manager)"
    say "uv installs into ~/.local/bin (user space — it does not touch system packages)."
    # why: we manage PATH ourselves (below) and print explicit rc-file instructions, so tell uv's
    # installer NOT to silently rewrite every shell rc file (.bashrc/.zshrc/.zshenv/.profile/…).
    curl -LsSf https://astral.sh/uv/install.sh | env INSTALLER_NO_MODIFY_PATH=1 UV_NO_MODIFY_PATH=1 sh
    export PATH="$HOME/.local/bin:$PATH"
fi
command -v uv >/dev/null 2>&1 || die "uv is still not on PATH — add ~/.local/bin to PATH and re-run."

step "set up Nabu (create the virtualenv, install dependencies)"
say "resolving Python packages into an isolated venv — cannot affect system packages."
(cd "$REPO" && uv sync)

# why: uv sync installs the console scripts into $REPO/.venv/bin, which is NOT on PATH — so a bare
# `nabu` / `nabu-cli` would say "command not found". Symlink them into ~/.local/bin (on Kali's PATH).
step "put nabu / nabu-cli on your PATH (~/.local/bin)"
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
for name in nabu nabu-cli; do
    if [ -x "$REPO/.venv/bin/$name" ]; then
        # never clobber a real file of the same name — only ever (re)create our own symlink
        if [ -e "$BIN_DIR/$name" ] && [ ! -L "$BIN_DIR/$name" ]; then
            warn "$BIN_DIR/$name exists and is not a symlink — left untouched (use 'uv run $name', or remove that file and re-run)."
            continue
        fi
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
trap - ERR INT TERM
printf '\n%s   ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄%s\n' "$GRN" "$R"
printf '%s   ✔ Setup complete — Nabu is installed.%s  %s(%ss)%s\n' "$GRN$B" "$R" "$DIM" "$SECONDS" "$R"
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
