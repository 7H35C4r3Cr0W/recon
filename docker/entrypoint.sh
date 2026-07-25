#!/usr/bin/env bash
# Nabu container entrypoint. Dispatches the headless CLI by default; `gui` launches the desktop app
# (needs an X11 socket forwarded from the host); `shell`/`bash` drops you into an interactive shell.
set -euo pipefail

# HOME is /data in the image, but honour --user / a different mount by re-deriving writable dirs.
: "${HOME:=/data}"
mkdir -p "$HOME/oscprecon" "$HOME/.config/oscprecon" 2>/dev/null || true

case "${1:-}" in
    gui | nabu)
        # the desktop GUI — requires -e DISPLAY + -v /tmp/.X11-unix:/tmp/.X11-unix from the host.
        # Check for a real SOCKET, not the directory: /tmp/.X11-unix already exists inside the
        # image (an apt postinst creates it), so `[ ! -e /tmp/.X11-unix ]` was always false and the
        # guard never fired — an unmounted display fell through to Qt and SIGSEGV'd (rc 139)
        # instead of printing these instructions. [review]
        x11_missing=0
        case "${DISPLAY:-}" in
            "") x11_missing=1 ;;
            :* | unix:*)
                # a unix display :N (optionally with a screen suffix) maps to /tmp/.X11-unix/XN
                dnum="${DISPLAY#unix:}"
                dnum="${dnum#:}"
                dnum="${dnum%%.*}"
                [ -S "/tmp/.X11-unix/X${dnum}" ] || x11_missing=1
                ;;
            *) : ;; # host:N / TCP display — nothing local to check, let Qt try
        esac
        if [ "$x11_missing" -eq 1 ]; then
            echo "[nabu] 'gui' needs a forwarded X11 display. Easiest: docker/nabu-docker.sh gui" >&2
            echo "       Manual: -e DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix  (+ 'xhost +local:' on host)." >&2
            echo "       No display? Recon works fully headless — just drop 'gui':" >&2
            echo "         docker run ... nabu doctor | scan IP -p NAME   (no display needed)." >&2
            exit 2
        fi
        exec nabu
        ;;
    shell | bash | sh)
        shift || true
        exec bash "$@"
        ;;
    cli | nabu-cli)
        shift
        exec nabu-cli "$@"
        ;;
    "" | help | -h | --help)
        exec nabu-cli --help
        ;;
    *)
        # any nabu-cli subcommand: doctor, scan, enum, searchsploit, payload, gtfobins, creds, …
        exec nabu-cli "$@"
        ;;
esac
