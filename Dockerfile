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
      nmap feroxbuster gobuster ffuf dirsearch nikto whatweb wpscan curl wget \
      smbclient smbmap enum4linux-ng impacket-scripts netexec \
      ldap-utils snmp onesixtyone dnsrecon bind9-dnsutils ike-scan nbtscan \
      ntpsec-ntpdate redis-tools nfs-common rpcbind dnsenum openssh-client rsync \
      ca-certificates git libcap2-bin procps iproute2 \
      python3 python3-venv \
      libgl1 libegl1 libglib2.0-0t64 libdbus-1-3 fontconfig fonts-dejavu-core \
      libxkbcommon0 libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
      libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 libxcb-xfixes0 \
      libnss3 libnspr4 libxcomposite1 libxdamage1 libxrandr2 libxtst6 libxi6 \
      libasound2t64 libcups2t64 libpango-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

# 2) Wordlists + Exploit-DB (heavy: ~2GB). On by default for a self-contained image; turn OFF for a
#    slim build and bind-mount host wordlists instead:  --build-arg WITH_WORDLISTS=0
ARG WITH_WORDLISTS=1
RUN if [ "$WITH_WORDLISTS" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends seclists exploitdb \
        && rm -rf /var/lib/apt/lists/* ; \
    else echo "WITH_WORDLISTS=0 — skipping seclists/exploitdb (mount host wordlists at runtime)"; fi

# let a non-root (--user) container still run SYN/UDP scans when granted CAP_NET_RAW
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)" || true

# 3) uv — pinned into /usr/local/bin; never let its installer rewrite shell rc files.
ENV UV_INSTALL_DIR=/usr/local/bin \
    INSTALLER_NO_MODIFY_PATH=1 \
    UV_NO_MODIFY_PATH=1
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && uv --version

# 4) Nabu into its own venv. Copy ONLY what the wheel needs (no dev cruft, no private files).
WORKDIR /opt/nabu
COPY pyproject.toml uv.lock README.md LICENSE ./
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
RUN mkdir -p /data/oscprecon /data/.config/oscprecon && chmod -R 0777 /data

COPY docker/entrypoint.sh /usr/local/bin/nabu-entrypoint
RUN chmod +x /usr/local/bin/nabu-entrypoint

WORKDIR /data
ENTRYPOINT ["/usr/local/bin/nabu-entrypoint"]
# bare `docker run nabu` → a friendly health check; override with any nabu-cli subcommand or `gui`.
CMD ["doctor"]
