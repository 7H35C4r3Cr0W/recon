#!/usr/bin/env bash
# Host-side launcher for the Nabu container. Works on ANY host with Docker — Kali, Parrot, Ubuntu,
# Fedora, Arch, macOS, Windows/WSL2 — because the Kali toolset lives inside the image, not on your
# host. Presets a persistent workspace volume, host networking (so a VPN tun + raw-socket scans work
# on Linux), and X11 forwarding for the desktop GUI.
#
#   docker/nabu-docker.sh build              # build (or rebuild) the image
#   docker/nabu-docker.sh doctor             # headless: check the toolset
#   docker/nabu-docker.sh scan 10.10.10.5 -p box   # headless: run a scan (persists to the volume)
#   docker/nabu-docker.sh gui                # desktop GUI (X11 forwarded)
#   docker/nabu-docker.sh shell              # interactive shell inside the container
#
# Env overrides:
#   NABU_IMAGE=nabu:latest        image tag to run/build
#   NABU_DATA=$HOME/.nabu         host dir for the persistent workspace (scans/creds/config)
#   NABU_USER="$(id -u):$(id -g)" run as this uid:gid so files are host-owned (default: root)
#   WITH_WORDLISTS=0              build a slim image without seclists/exploitdb (~2GB smaller)
set -euo pipefail

IMAGE="${NABU_IMAGE:-nabu:latest}"
DATA="${NABU_DATA:-$HOME/.nabu}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

c_die() { printf '\033[1;31m[nabu-docker] %s\033[0m\n' "$*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || c_die "docker is not installed. Install Docker Engine (Linux) or Docker Desktop, then re-run."

usage() {
    cat <<EOF
Nabu (containerized) — recon-first, OSCP exam-legal. Runs on any host with Docker.

USAGE
  docker/nabu-docker.sh <command> [args…]

COMMANDS
  build                 build/rebuild the image (${IMAGE})
  doctor                check the wrapped tools inside the container
  scan <ip> -p <name>   run a scan; results persist under \$NABU_DATA (${DATA})
  enum <service> …      headless service recon (see: … cli enum --help)
  searchsploit <q>      offline Exploit-DB lookup
  <any nabu-cli cmd>    anything nabu-cli accepts is passed straight through
  gui                   launch the desktop GUI (forwards your X11 display)
  shell                 open a shell inside the container
  help                  this screen  (per-command help:  … <cmd> --help)

NOTES
  • Persistent data lives on the host at \$NABU_DATA (${DATA}) → /data in the container.
  • Uses --network host so a VPN tun + raw-socket nmap work on rootful Docker Engine (the Kali/
    Parrot/Ubuntu default). On macOS/Windows Docker Desktop — and under rootless Docker / Podman —
    host networking + raw sockets are limited; the CLI still works and nmap degrades to connect scans.
  • GUI needs an X11 server on the host (Linux/Parrot: native; macOS: XQuartz; Windows: WSLg/VcXsrv).
    On SELinux-enforcing hosts the GUI may also need --security-opt label=disable for the X socket.
  • Files in \$NABU_DATA are root-owned by default; set NABU_USER="\$(id -u):\$(id -g)" for host ownership.
EOF
}

ensure_image() {
    docker image inspect "$IMAGE" >/dev/null 2>&1 && return 0
    printf '\033[1;36m[nabu-docker] image %s not found — building it once…\033[0m\n' "$IMAGE" >&2
    build
}

build() {
    local args=(build -t "$IMAGE")
    [ -n "${WITH_WORDLISTS:-}" ] && args+=(--build-arg "WITH_WORDLISTS=${WITH_WORDLISTS}")
    args+=("$REPO")
    printf '\033[1;36m[nabu-docker] docker %s\033[0m\n' "${args[*]}" >&2
    docker "${args[@]}"
}

mkdir -p "$DATA"

# shared docker run flags: host net (VPN/raw scans), recon caps, persistent volume, optional --user
common_flags() {
    printf '%s\0' --rm -i
    [ -t 0 ] && printf '%s\0' -t
    printf '%s\0' --network host
    # only cap scanning needs; nmap has cap_net_raw+ep so this also enables SYN scans under --user.
    printf '%s\0' --cap-add=NET_RAW
    # :z relabels for SELinux hosts (Fedora/RHEL) and is a no-op elsewhere (Kali/Parrot/Ubuntu/Arch).
    printf '%s\0' -v "$DATA:/data:z"
    [ -n "${NABU_USER:-}" ] && printf '%s\0' --user "$NABU_USER"
}

run_container() { # run_container <container-args…>
    local flags=()
    while IFS= read -r -d '' f; do flags+=("$f"); done < <(common_flags)
    exec docker run "${flags[@]}" "$IMAGE" "$@"
}

cmd="${1:-help}"
case "$cmd" in
    build)
        shift
        build "$@"
        ;;
    gui)
        ensure_image
        [ -n "${DISPLAY:-}" ] || c_die "no \$DISPLAY set — start an X11 server (Parrot/Kali have one) or use the CLI."
        local_flags=()
        while IFS= read -r -d '' f; do local_flags+=("$f"); done < <(common_flags)
        # grant the container access to the host X server, then REVOKE it when the GUI exits — run
        # docker in the FOREGROUND (not exec) so this trap fires. (No --ipc=host: MIT-SHM is off and
        # QtWebEngine runs --disable-dev-shm-usage, so sharing the host IPC namespace buys nothing.)
        if command -v xhost >/dev/null 2>&1; then
            xhost +local: >/dev/null 2>&1 || true
            trap 'xhost -local: >/dev/null 2>&1 || true' EXIT INT TERM
        fi
        docker run "${local_flags[@]}" \
            -e DISPLAY="$DISPLAY" \
            -e QT_X11_NO_MITSHM=1 \
            -v /tmp/.X11-unix:/tmp/.X11-unix:rw \
            "$IMAGE" gui
        ;;
    shell)
        ensure_image
        run_container shell
        ;;
    help | -h | --help | "")
        usage
        ;;
    *)
        ensure_image
        run_container "$@"
        ;;
esac
