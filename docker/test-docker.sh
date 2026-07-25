#!/usr/bin/env bash
# End-to-end verification of the CONTAINERIZED Nabu — the checks that caught every real Docker bug
# so far (dead GUI from missing xcb libs, nmap EPERM from Kali's cap_net_admin, non-root file
# ownership, entrypoint dispatch). Run it after touching the Dockerfile, the entrypoint, or the
# host launcher; it never writes to your real workspace (it uses a throwaway NABU_DATA).
#
#   docker/test-docker.sh                 static checks + container checks (image must exist)
#   docker/test-docker.sh --static        static checks only — no Docker needed (CI-safe)
#   docker/test-docker.sh --build         (re)build the image first, then run everything
#   docker/test-docker.sh --net           also scan scanme.nmap.org (needs internet; opt-in)
#   docker/test-docker.sh --gui           also smoke the X11 GUI path (needs $DISPLAY)
#   docker/test-docker.sh --keep          keep the throwaway workspace for inspection
#
# Env: NABU_IMAGE (default nabu:latest). Exit 0 = all green, 1 = at least one failure.
# why no `set -e`: every check runs even after one fails, so a single run reports the full picture.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${NABU_IMAGE:-nabu:latest}"
WRAPPER="$REPO/docker/nabu-docker.sh"

STATIC_ONLY=0
DO_BUILD=0
DO_NET=0
DO_GUI=0
KEEP=0
for arg in "$@"; do
    case "$arg" in
        --static | --static-only) STATIC_ONLY=1 ;;
        --build) DO_BUILD=1 ;;
        --net) DO_NET=1 ;;
        --gui) DO_GUI=1 ;;
        --keep) KEEP=1 ;;
        -h | --help)
            sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            printf 'unknown option: %s (try --help)\n' "$arg" >&2
            exit 2
            ;;
    esac
done

PASS=0
FAIL=0
SKIP=0
FAILED_NAMES=()
C_OK=$'\033[1;32m'
C_NO=$'\033[1;31m'
C_SK=$'\033[1;33m'
C_HD=$'\033[1;36m'
C_Z=$'\033[0m'
[ -t 1 ] || { C_OK=""; C_NO=""; C_SK=""; C_HD=""; C_Z=""; }

section() { printf '\n%s── %s %s\n' "$C_HD" "$1" "$C_Z"; }
ok() { PASS=$((PASS + 1)); printf '  %sPASS%s  %s\n' "$C_OK" "$C_Z" "$1"; }
no() {
    FAIL=$((FAIL + 1))
    FAILED_NAMES+=("$1")
    printf '  %sFAIL%s  %s\n' "$C_NO" "$C_Z" "$1"
    [ -n "${2:-}" ] && printf '        %s\n' "$2"
    return 0
}
skip() { SKIP=$((SKIP + 1)); printf '  %sSKIP%s  %s — %s\n' "$C_SK" "$C_Z" "$1" "${2:-}"; }

# check <name> <command…> — passes when the command exits 0; shows the tail of its output on failure.
check() {
    local name="$1"
    shift
    local out
    if out="$("$@" 2>&1)"; then
        ok "$name"
    else
        no "$name" "$(printf '%s' "$out" | tail -3 | tr '\n' ' ')"
    fi
}

# grep_file <name> <file> <pattern> — the file must contain the (extended) pattern.
grep_file() {
    local name="$1" file="$2" pattern="$3"
    if grep -Eq -- "$pattern" "$file" 2>/dev/null; then
        ok "$name"
    else
        no "$name" "missing /$pattern/ in ${file#"$REPO"/}"
    fi
}

###############################################################################################
section "static — repository assets (no Docker needed)"
###############################################################################################
for f in Dockerfile docker-compose.yml .dockerignore docker/entrypoint.sh docker/nabu-docker.sh \
    docker/test-docker.sh; do
    if [ -f "$REPO/$f" ]; then ok "exists: $f"; else no "exists: $f"; fi
done
for f in docker/entrypoint.sh docker/nabu-docker.sh docker/test-docker.sh install.sh; do
    if [ -x "$REPO/$f" ]; then ok "executable: $f"; else no "executable: $f" "chmod +x it"; fi
    if [ -f "$REPO/$f" ]; then check "shell syntax: $f" bash -n "$REPO/$f"; fi
done

# the build context must never carry maintainer-private or heavy paths into a distributable image
for private in HANDOFF.local.md walkthroughs/ .claude/ .venv .git tests/; do
    bare="${private%/}"
    grep_file ".dockerignore excludes $private" "$REPO/.dockerignore" "^${bare//./\\.}/?$"
done

# Dockerfile invariants — each of these encodes a bug we already fixed once.
grep_file "Dockerfile: Kali base"            "$REPO/Dockerfile" '^FROM kalilinux/kali-rolling'
grep_file "Dockerfile: HOME=/data"           "$REPO/Dockerfile" 'HOME=/data'
grep_file "Dockerfile: entrypoint installed" "$REPO/Dockerfile" 'ENTRYPOINT \["/usr/local/bin/nabu-entrypoint"\]'
grep_file "Dockerfile: nmap re-capped to cap_net_raw (EPERM fix)" \
    "$REPO/Dockerfile" 'setcap cap_net_raw\+ep /usr/lib/nmap/nmap'
grep_file "Dockerfile: deps layer cached before src" \
    "$REPO/Dockerfile" 'uv sync --frozen --no-dev --no-install-project'
grep_file "Dockerfile: uv from signed image (no curl|sh)" \
    "$REPO/Dockerfile" '^COPY --from=ghcr.io/astral-sh/uv'
# the xcb/WebEngine runtime libs whose absence made the GUI 100% dead in-container
for lib in libxcb-xkb1 libxkbcommon-x11-0 libxfixes3 libxkbfile1 libnss3 libxcb-cursor0; do
    grep_file "Dockerfile: GUI lib $lib" "$REPO/Dockerfile" "(^| )$lib( |\\\\|$)"
done
# comment lines are stripped first: the Dockerfile *documents* why it avoids piping curl into a shell
if grep -v '^[[:space:]]*#' "$REPO/Dockerfile" | grep -Eq 'curl[^|]*\| *(sudo *)?(ba)?sh'; then
    no "Dockerfile: no piped curl|sh at build time"
else
    ok "Dockerfile: no piped curl|sh at build time"
fi

# entrypoint dispatch table. FIXED-string matching on the actual `case` labels: as an extended
# regex, `gui | nabu` is the alternation "gui " OR " nabu", which matches almost any shell script —
# those four checks passed vacuously until this was caught.
for label in 'gui | nabu)' 'shell | bash | sh)' 'cli | nabu-cli)' '"" | help | -h | --help)'; do
    if grep -Fq -- "$label" "$REPO/docker/entrypoint.sh"; then
        ok "entrypoint dispatches: $label"
    else
        no "entrypoint dispatches: $label" "no such case label in docker/entrypoint.sh"
    fi
done
grep_file "entrypoint: friendly no-DISPLAY guidance" "$REPO/docker/entrypoint.sh" 'needs a forwarded X11 display'

# host launcher + compose must agree on the defaults, or the two entry points split the workspace
grep_file "launcher: default image nabu:latest"  "$WRAPPER" 'NABU_IMAGE:-nabu:latest'
grep_file "launcher: default data \$HOME/.nabu"  "$WRAPPER" 'NABU_DATA:-\$HOME/\.nabu'
grep_file "launcher: --network host"             "$WRAPPER" '\-\-network host'
grep_file "launcher: --cap-add=NET_RAW"          "$WRAPPER" '\-\-cap-add=NET_RAW'
grep_file "launcher: SELinux :z volume label"    "$WRAPPER" 'DATA:/data:z'
grep_file "launcher: X cookie auth (no xhost dependency)" "$WRAPPER" 'XAUTHORITY'
grep_file "compose: same default data dir"       "$REPO/docker-compose.yml" 'NABU_DATA:-\$\{HOME\}/\.nabu\}:/data:z'
grep_file "compose: same default image tag"      "$REPO/docker-compose.yml" 'NABU_IMAGE:-nabu:latest'
grep_file "compose: NET_RAW"                     "$REPO/docker-compose.yml" 'NET_RAW'

if [ "$STATIC_ONLY" = 1 ]; then
    section "summary (static only)"
    printf '  %s%d passed%s, %s%d failed%s, %d skipped\n' \
        "$C_OK" "$PASS" "$C_Z" "$C_NO" "$FAIL" "$C_Z" "$SKIP"
    [ "$FAIL" -eq 0 ] || printf '  failed: %s\n' "${FAILED_NAMES[*]}"
    exit $((FAIL > 0))
fi

###############################################################################################
section "container — image + runtime"
###############################################################################################
if ! command -v docker >/dev/null 2>&1; then
    skip "container checks" "docker is not installed (run with --static for the rest)"
    section "summary"
    printf '  %s%d passed%s, %s%d failed%s, %d skipped\n' \
        "$C_OK" "$PASS" "$C_Z" "$C_NO" "$FAIL" "$C_Z" "$SKIP"
    exit $((FAIL > 0))
fi

if [ "$DO_BUILD" = 1 ]; then
    printf '  building %s (this takes a few minutes)…\n' "$IMAGE"
    check "image builds" "$WRAPPER" build
elif ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    printf '  image %s not found — building it once…\n' "$IMAGE"
    check "image builds" "$WRAPPER" build
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    no "image available: $IMAGE" "build failed — the remaining container checks cannot run"
    section "summary"
    printf '  %s%d passed%s, %s%d failed%s, %d skipped\n' \
        "$C_OK" "$PASS" "$C_Z" "$C_NO" "$FAIL" "$C_Z" "$SKIP"
    exit 1
fi
ok "image available: $IMAGE"

# a throwaway workspace so a test run can never disturb the operator's real ~/.nabu
DATA="$(mktemp -d -t nabu-docker-test.XXXXXX)"
cleanup() {
    if [ "$KEEP" = 1 ]; then
        printf '\n  workspace kept at %s\n' "$DATA"
        return
    fi
    # the default (root) runs leave root-owned files behind — hand them back before rm.
    docker run --rm -v "$DATA:/data:z" --entrypoint chown "$IMAGE" \
        -R "$(id -u):$(id -g)" /data >/dev/null 2>&1 || true
    rm -rf "$DATA"
}
trap cleanup EXIT

# drun <container-args…> — a plain container run against the throwaway workspace.
drun() {
    docker run --rm --network host --cap-add=NET_RAW -v "$DATA:/data:z" "$IMAGE" "$@"
}
# drun_user — same, as the invoking (non-root) user: the host-ownership + raw-scan combination.
drun_user() {
    docker run --rm --network host --cap-add=NET_RAW --user "$(id -u):$(id -g)" \
        -v "$DATA:/data:z" "$IMAGE" "$@"
}
# dsh <script> — run a shell snippet inside the container via the entrypoint's `shell` dispatch.
dsh() { drun shell -c "$1"; }

check "entrypoint: bare run defaults to doctor" bash -c \
    "docker run --rm -v '$DATA:/data:z' '$IMAGE' | grep -qiE 'doctor|tool'"
check "entrypoint: nabu-cli passthrough (--help)" bash -c \
    "docker run --rm -v '$DATA:/data:z' '$IMAGE' --help | grep -q 'Usage'"
check "entrypoint: shell dispatch executes" bash -c \
    "docker run --rm -v '$DATA:/data:z' '$IMAGE' shell -c 'echo container-shell-ok' | grep -q container-shell-ok"
# `gui` with no DISPLAY must fail LOUDLY with guidance, not a cryptic Qt xcb abort
gui_out="$(docker run --rm -e DISPLAY= -v "$DATA:/data:z" "$IMAGE" gui 2>&1)"
gui_rc=$?
if [ "$gui_rc" -eq 2 ] && printf '%s' "$gui_out" | grep -q 'forwarded X11 display'; then
    ok "entrypoint: gui without DISPLAY exits 2 with guidance"
else
    no "entrypoint: gui without DISPLAY exits 2 with guidance" "rc=$gui_rc out=${gui_out:0:120}"
fi

section "container — the wrapped toolset"
CORE_TOOLS="nmap feroxbuster gobuster ffuf dirsearch nikto whatweb wpscan smbclient smbmap"
CORE_TOOLS="$CORE_TOOLS enum4linux-ng netexec rpcclient ldapsearch snmpwalk onesixtyone dnsrecon"
CORE_TOOLS="$CORE_TOOLS dig ike-scan nbtscan ntpq curl wget ssh rsync showmount redis-cli"
# why the PROBE_RAN sentinel: "no output means every tool is present" also holds when the probe
# never ran at all (a broken entrypoint, a failed container start), which would turn this check
# green on a completely dead image. Require positive proof that the loop executed.
TOOL_PROBE="$(dsh "for t in $CORE_TOOLS; do command -v \"\$t\" >/dev/null 2>&1 || echo \"MISSING \$t\"; done; echo PROBE_RAN" 2>/dev/null)"
MISSING_TOOLS="$(printf '%s\n' "$TOOL_PROBE" | sed -n 's/^MISSING //p' | tr '\n' ' ')"
if ! printf '%s' "$TOOL_PROBE" | grep -q PROBE_RAN; then
    no "core recon tools present in the image" "the probe itself did not run inside the container"
elif [ -z "${MISSING_TOOLS// /}" ]; then
    ok "core recon tools present in the image"
else
    no "core recon tools present in the image" "missing: $MISSING_TOOLS"
fi
# Kali installs impacket WITHOUT the .py suffix — the detection bug that showed tools as missing
check "impacket scripts present (no-.py Kali names)" bash -c \
    "docker run --rm -v '$DATA:/data:z' '$IMAGE' shell -c 'command -v impacket-secretsdump && command -v impacket-GetUserSPNs' >/dev/null"
# doctor's own view: a CORE tool must never appear in its missing list. (Optional extras — awscli,
# windapsearch, mongosh — may legitimately be absent; doctor prints them as install hints.)
DOCTOR_OUT="$(drun doctor 2>&1)"
DOCTOR_GAPS=""
for t in nmap feroxbuster gobuster ffuf nikto whatweb wpscan smbclient smbmap netexec rpcclient \
    ldapsearch snmpwalk dnsrecon dig ike-scan nbtscan searchsploit hashcat john nc evil-winrm \
    certipy responder hydra medusa mysql psql wfuzz finger dirb svn; do
    printf '%s' "$DOCTOR_OUT" | grep -qE "^ +$t +" && DOCTOR_GAPS="$DOCTOR_GAPS $t"
done
if [ -z "$DOCTOR_GAPS" ]; then
    ok "doctor reports no core tool missing"
else
    no "doctor reports no core tool missing" "missing:$DOCTOR_GAPS"
fi
check "doctor finds the bundled wordlists + Exploit-DB" bash -c \
    "printf '%s' \"\$(docker run --rm '$IMAGE' doctor 2>&1)\" | grep -q 'ok  SecLists wordlists'"

section "container — nmap actually runs (cap_net_admin EPERM regression)"
check "nmap --version executes" bash -c "docker run --rm '$IMAGE' shell -c 'nmap --version' >/dev/null"
check "nmap raw SYN scan works as root" bash -c \
    "docker run --rm --network host --cap-add=NET_RAW '$IMAGE' shell -c 'nmap -sS -Pn -p 22 127.0.0.1' | grep -q '22/tcp'"
check "nmap raw SYN scan works as --user (non-root)" bash -c \
    "docker run --rm --network host --cap-add=NET_RAW --user '$(id -u):$(id -g)' '$IMAGE' shell -c 'nmap -sS -Pn -p 22 127.0.0.1' | grep -q '22/tcp'"

section "container — GUI runtime (no X server needed)"
check "PySide6 widgets import" bash -c \
    "docker run --rm '$IMAGE' shell -c 'python -c \"import PySide6.QtWidgets\"'"
check "QtWebEngine import (reference pane / graph)" bash -c \
    "docker run --rm '$IMAGE' shell -c 'python -c \"import PySide6.QtWebEngineWidgets\"'"
# same trap as above: an empty "not found" list is also what a probe that never located the plugin
# produces. Print the ldd line count so a silent probe failure fails the check instead of passing it.
XCB_PROBE="$(dsh 'p=$(python -c "import PySide6,os;print(os.path.dirname(PySide6.__file__))")/Qt/plugins/platforms/libqxcb.so; test -f "$p" || { echo NO_PLUGIN; exit 0; }; ldd "$p" 2>/dev/null | grep "not found"; echo "LDD_LINES=$(ldd "$p" 2>/dev/null | wc -l)"' 2>/dev/null)"
XCB_LINES="$(printf '%s' "$XCB_PROBE" | sed -n 's/^LDD_LINES=//p')"
if printf '%s' "$XCB_PROBE" | grep -q NO_PLUGIN || [ "${XCB_LINES:-0}" -lt 5 ]; then
    no "xcb platform plugin has no unresolved libraries" "the ldd probe did not run (plugin missing?)"
elif printf '%s' "$XCB_PROBE" | grep -q 'not found'; then
    no "xcb platform plugin has no unresolved libraries" \
        "$(printf '%s' "$XCB_PROBE" | grep 'not found' | tr '\n' ' ')"
else
    ok "xcb platform plugin has no unresolved libraries ($XCB_LINES libs resolved)"
fi
# the app must actually BOOT: offscreen needs no X server, so a crash-on-start shows up as an early
# exit while a healthy app stays alive until the timeout kills it (rc 124). why the trailing echo:
# without it bash execs `timeout` as PID 1, where it can't signal itself and reports its own
# internal-error 125 instead of 124 — a harness artifact, not an app failure.
boot_out="$(docker run --rm -e QT_QPA_PLATFORM=offscreen -v "$DATA:/data:z" "$IMAGE" \
    shell -c 'timeout 40 nabu; echo "boot_rc=$?"' 2>&1)"
if printf '%s' "$boot_out" | grep -q 'boot_rc=124'; then
    ok "GUI boots offscreen and stays up"
else
    no "GUI boots offscreen and stays up" "$(printf '%s' "$boot_out" | tail -2 | tr '\n' ' ')"
fi

section "container — workspace persistence on the host volume"
# a profile.json is written even when nmap finds nothing (or cannot run at all), so persistence
# alone is a weak assertion — require that the scan actually DISCOVERED a service through it.
drun scan 127.0.0.1 -p dockersmoke --scan-profile quick >/dev/null 2>&1 || true
if [ -f "$DATA/oscprecon/dockersmoke/profile.json" ]; then
    ok "scan writes a profile to the mounted volume"
else
    no "scan writes a profile to the mounted volume"
fi
# Read it back THROUGH the container: the default run is root and profile.json is mode 0600, so a
# host-side grep gets "Permission denied" and would report an empty scan that actually worked.
# `list` prints SVC/FIND/CRED — a non-zero service count is the proof nmap really enumerated
# something (findings stay 0 here: a bare scan discovers services, the service modules find things).
SVC_COUNT="$(drun list 2>/dev/null | awk '$1 == "dockersmoke" {print $NF}' | cut -d/ -f1)"
if [ "${SVC_COUNT:-0}" -gt 0 ] 2>/dev/null; then
    ok "the scan really enumerated services ($SVC_COUNT found, not just an empty profile)"
else
    no "the scan really enumerated services (not just an empty profile)" \
        "0 services recorded — nmap ran but found nothing, or could not run"
fi
check "a second container sees the persisted project" bash -c \
    "docker run --rm -v '$DATA:/data:z' '$IMAGE' list | grep -q dockersmoke"
check "config lives under the single /data mount" bash -c "test -d '$DATA/.config/oscprecon'"
check "findings survive the container exiting" bash -c \
    "docker run --rm -v '$DATA:/data:z' '$IMAGE' findings -p dockersmoke >/dev/null"

section "container — non-root run (host-owned files)"
# a FRESH workspace: the default (root) runs above leave root-owned dirs, which a --user run
# legitimately cannot write — that trap is checked separately below.
UDATA="$(mktemp -d -t nabu-docker-user.XXXXXX)"
cleanup_user() { [ "$KEEP" = 1 ] || rm -rf "$UDATA"; }
trap 'cleanup; cleanup_user' EXIT  # both workspaces, however the run ends
if docker run --rm --network host --cap-add=NET_RAW --user "$(id -u):$(id -g)" \
    -v "$UDATA:/data:z" "$IMAGE" scan 127.0.0.1 -p userowned --scan-profile quick >/dev/null 2>&1
then
    owner="$(stat -c '%u' "$UDATA/oscprecon/userowned/profile.json" 2>/dev/null || echo "?")"
    if [ "$owner" = "$(id -u)" ]; then
        ok "NABU_USER run leaves host-owned files (uid $owner)"
    else
        no "NABU_USER run leaves host-owned files" "profile.json owned by uid $owner, expected $(id -u)"
    fi
else
    no "NABU_USER run completes a scan on a fresh workspace"
fi
[ "$KEEP" = 1 ] && printf '  non-root workspace kept at %s\n' "$UDATA"
# the launcher must WARN before a --user run hits a root-owned workspace, instead of letting the
# operator discover it as a permission error mid-scan.
warn_out="$(NABU_DATA="$DATA" NABU_USER="$(id -u):$(id -g)" "$WRAPPER" help 2>&1 >/dev/null)"
if printf '%s' "$warn_out" | grep -q 'chown'; then
    ok "launcher warns about a root-owned workspace under NABU_USER"
else
    no "launcher warns about a root-owned workspace under NABU_USER" "no warning emitted"
fi

if [ "$DO_NET" = 1 ]; then
    section "container — live internet scan (opt-in)"
    check "scan scanme.nmap.org discovers services" bash -c \
        "docker run --rm --network host --cap-add=NET_RAW -v '$DATA:/data:z' '$IMAGE' \
         scan scanme.nmap.org -p dockernet --scan-profile quick >/dev/null 2>&1; \
         docker run --rm -v '$DATA:/data:z' '$IMAGE' list | grep -q dockernet"
else
    skip "live internet scan" "opt-in: re-run with --net"
fi

if [ "$DO_GUI" = 1 ]; then
    section "container — X11 GUI through the host launcher (opt-in)"
    if [ -z "${DISPLAY:-}" ]; then
        skip "launcher gui" "no \$DISPLAY on this host"
    else
        # `timeout` cannot stop `docker run -t` (the CLI does not proxy the signal), so the old
        # form hung forever and left a container running. Name it, then force-remove it. [review]
        gui_name="nabu-gui-smoke-$$"
        gui_out="$(mktemp)"
        NABU_DATA="$DATA" NABU_DOCKER_NAME="$gui_name" "$WRAPPER" gui >"$gui_out" 2>&1 </dev/null &
        gui_pid=$!
        sleep 20
        if docker ps --filter "name=^${gui_name}$" --format '{{.Names}}' | grep -q "$gui_name"; then
            ok "launcher gui opens and stays up on \$DISPLAY"
        else
            no "launcher gui opens and stays up on \$DISPLAY" "$(tail -2 "$gui_out" | tr '\n' ' ')"
        fi
        docker rm -f "$gui_name" >/dev/null 2>&1 || true
        wait "$gui_pid" 2>/dev/null || true
        rm -f "$gui_out"
    fi
else
    skip "X11 GUI smoke" "opt-in: re-run with --gui"
fi

section "summary"
printf '  %s%d passed%s, %s%d failed%s, %d skipped\n' \
    "$C_OK" "$PASS" "$C_Z" "$C_NO" "$FAIL" "$C_Z" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
    printf '  %sfailed:%s\n' "$C_NO" "$C_Z"
    for n in "${FAILED_NAMES[@]}"; do printf '    • %s\n' "$n"; done
fi
exit $((FAIL > 0))
