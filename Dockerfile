# syntax=docker/dockerfile:1
###############################################################################################
# Nabu — containerized recon workspace (recon-first, OSCP exam-legal)
#
# HOST-OS-INDEPENDENT BY DESIGN. The Kali userland (every wrapped recon tool) lives INSIDE this
# image, so the same container runs identically on Kali, Parrot, Ubuntu, Fedora, Arch, macOS and
# Windows/WSL2 — anywhere Docker runs. The host's apt/dpkg is never touched, which is the clean
# answer to cross-distro package drift (no partial upgrades, no renamed packages, no broken apt).
#
# Build:  docker build -t nabu:latest .
#         docker build --build-arg WITH_WORDLISTS=0 -t nabu:slim .   # skip the ~2GB data sets
# Run:    docker run --rm -it --network host --cap-add=NET_RAW -v "$HOME/.nabu:/data" nabu doctor
#         (or use the helper: docker/nabu-docker.sh doctor|scan …|gui|shell)
###############################################################################################
FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.title="Nabu" \
      org.opencontainers.image.description="Recon-first, OSCP exam-legal enumeration workspace (Kali toolset baked in)" \
      org.opencontainers.image.source="https://github.com/7H35C4r3Cr0W/recon" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# 1) Recon tool set (CLAUDE.md §4) + Qt6/QtWebEngine runtime libs for the GUI + python/uv prereqs.
#    ONE transaction, --no-install-recommends, names verified on kali-rolling. PySide6 bundles Qt
#    itself, so only the system libs Qt's xcb platform and Chromium dlopen are needed here.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap feroxbuster gobuster ffuf dirsearch dirb nikto whatweb wpscan curl wget wfuzz \
      smbclient smbmap enum4linux-ng enum4linux impacket-scripts netexec \
      ldap-utils snmp snmpcheck onesixtyone dnsrecon bind9-dnsutils ike-scan nbtscan \
      ntpsec-ntpdate ntpsec redis-tools nfs-common rpcbind dnsenum openssh-client ssh-audit rsync \
      finger subversion default-mysql-client postgresql-client netcat-traditional \
      ca-certificates git libcap2-bin procps iproute2 \
      python3 python3-venv \
      libgl1 libegl1 libglib2.0-0t64 libdbus-1-3 fontconfig fonts-dejavu-core \
      libxkbcommon0 libxkbcommon-x11-0 libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
      libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 libxcb-xfixes0 libxcb-xkb1 \
      libnss3 libnspr4 libxcomposite1 libxdamage1 libxrandr2 libxtst6 libxi6 libxfixes3 libxkbfile1 \
      libasound2t64 libcups2t64 libpango-1.0-0 libwayland-cursor0 \
    && rm -rf /var/lib/apt/lists/*

# 2) Wordlists + Exploit-DB (heavy: ~2GB). On by default for a self-contained image; turn OFF for a
#    slim build and bind-mount host wordlists instead:  --build-arg WITH_WORDLISTS=0
ARG WITH_WORDLISTS=1
RUN if [ "$WITH_WORDLISTS" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends seclists exploitdb wordlists \
        && rm -rf /var/lib/apt/lists/* ; \
    else echo "WITH_WORDLISTS=0 — skipping seclists/exploitdb (mount host wordlists at runtime)"; fi

# 2b) Exploitation-tab (§2b) + Spray-mode (§2a) tools. NOT used by default recon — the recon
#     allow-list never runs them — but the attack catalog and `doctor` expect them, and a user who
#     builds this image wants the box to be complete. Turn off for a recon-only image:
#     --build-arg WITH_ATTACK=0
ARG WITH_ATTACK=1
RUN if [ "$WITH_ATTACK" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
          evil-winrm certipy-ad responder john hashcat hydra medusa \
        && rm -rf /var/lib/apt/lists/* ; \
    else echo "WITH_ATTACK=0 — skipping the exploitation/spray tool set (recon-only image)"; fi

# 3) uv — copied from the official distroless image (no `curl | sh` piped to a root shell at build
#    time; reproducible and signed via the image digest).
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/
RUN uv --version

# 4) Nabu into its own venv. Copy ONLY what the wheel needs (no dev cruft, no private files).
#    Install DEPENDENCIES first (this heavy layer — PySide6 etc. — is cached across source edits),
#    then the project itself, so iterating on src doesn't re-download Qt every build.
WORKDIR /opt/nabu
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev \
    && rm -rf /root/.cache/uv
ENV PATH="/opt/nabu/.venv/bin:${PATH}"

# 5) Runtime env. HOME=/data so the workspace (~/oscprecon), config, cache and state ALL live under a
#    single /data volume — one bind mount persists everything. The GUI's Chromium flags are set for a
#    sandbox-less container; QT_QPA_PLATFORM=xcb targets a forwarded X11 socket (the GUI is opt-in).
ENV HOME=/data \
    QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox --disable-gpu --disable-gpu-compositing --disable-dev-shm-usage" \
    QT_QPA_PLATFORM=xcb
# /data is the single persistence mount (workspace/config/cache/state all live under HOME=/data).
# Make ONLY the mount point writable by any uid so a --user (non-root) run can create its subtree on a
# fresh named volume; the entrypoint mkdir -p's the actual dirs, owned by the runtime user.
RUN mkdir -p /data && chmod 0777 /data

# Kali's nmap ships the REAL binary /usr/lib/nmap/nmap (/usr/bin/nmap is a wrapper script) with
# cap_net_admin set — that cap is NOT in Docker's default bounding set, so with the effective bit the
# kernel REFUSES to exec nmap (EPERM: "Operation not permitted") in a normal container. Re-cap the
# real binary to cap_net_raw ONLY (which IS in the default set): raw scans work everywhere — a bare
# `docker run` as root, or --user + --cap-add=NET_RAW — and nmap never fails to launch. (Kept as a
# late layer so tweaking it doesn't invalidate the cached dependency install above.)
RUN setcap cap_net_raw+ep /usr/lib/nmap/nmap 2>/dev/null || true

COPY docker/entrypoint.sh /usr/local/bin/nabu-entrypoint
RUN chmod +x /usr/local/bin/nabu-entrypoint

WORKDIR /data
ENTRYPOINT ["/usr/local/bin/nabu-entrypoint"]
# bare `docker run nabu` → a friendly health check; override with any nabu-cli subcommand or `gui`.
CMD ["doctor"]
