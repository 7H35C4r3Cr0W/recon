#!/usr/bin/env bash
# Nabu container entrypoint. Dispatches the headless CLI by default; `gui` launches the desktop app
# (needs an X11 socket forwarded from the host); `shell`/`bash` drops you into an interactive shell.
set -euo pipefail

# HOME is /data in the image, but honour --user / a different mount by re-deriving writable dirs.
: "${HOME:=/data}"
mkdir -p "$HOME/oscprecon" "$HOME/.config/oscprecon" 2>/dev/null || true

case "${1:-}" in
    gui | nabu)
        # the desktop GUI — requires -e DISPLAY + -v /tmp/.X11-unix:/tmp/.X11-unix from the host
        if [ -z "${DISPLAY:-}" ]; then
            echo "[nabu] 'gui' needs an X11 display. Re-run via docker/nabu-docker.sh gui, or pass" >&2
            echo "       -e DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix (and 'xhost +local:' on the host)." >&2
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
