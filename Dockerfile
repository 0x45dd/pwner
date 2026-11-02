# pwner in a container — the least-setup way to get the whole toolchain.
#
# Build:
#   docker build -t pwner .
#
# Run (see README: --net=host and NET_RAW/NET_ADMIN are what make nmap's SYN scans and
# ICMP/ARP host discovery work; without them nmap silently falls back to slower, weaker
# connect scans and misses hosts):
#   docker run --rm -it --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
#     -v pwner-config:/root/.config/pwner -v pwner-sessions:/root/.local/share/pwner pwner
#
# The volumes persist the saved API key and the /dump transcripts; without them both are
# lost when the container exits.
FROM python:3.12-slim

# One layer for the OS-packaged tools. `snmp` is the package that provides snmpwalk.
# exploitdb is deliberately absent: it is a Kali package, not a Debian one, so
# `apt-get install exploitdb` fails on this base. See WITH_EXPLOITDB below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        hydra \
        snmp \
        hashcat \
        git \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# nuclei ships prebuilt per-arch; pick the right asset instead of building Go here.
ARG NUCLEI_VERSION=3.11.1
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) na=amd64 ;; \
        arm64) na=arm64 ;; \
        *) echo "unsupported arch $arch" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${na}.zip"; \
    apt-get update && apt-get install -y --no-install-recommends unzip; \
    curl -fsSL "$url" -o /tmp/nuclei.zip; \
    unzip -j /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    chmod +x /usr/local/bin/nuclei; \
    rm /tmp/nuclei.zip; \
    apt-get purge -y unzip; apt-get autoremove -y; rm -rf /var/lib/apt/lists/*

# The Python-ecosystem tools. Each gets its own venv via pipx so their pinned
# dependencies cannot conflict with each other or with pwner's.
# netexec is NOT on PyPI — it has to come from the repository.
ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
RUN pip install --no-cache-dir pipx \
    && pipx install impacket \
    && pipx install certipy-ad \
    && pipx install bloodhound \
    && pipx install git+https://github.com/Pennyw0rth/NetExec \
    && rm -rf /root/.cache

# ExploitDB is off by default: searchsploit needs the whole exploit corpus locally, which
# adds roughly a gigabyte for one optional tool. exploit_search still works without it —
# it falls back to the local nuclei template index. Turn it on with:
#   docker build --build-arg WITH_EXPLOITDB=1 -t pwner .
ARG WITH_EXPLOITDB=0
RUN if [ "$WITH_EXPLOITDB" = "1" ]; then \
        git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
        && ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit; \
    fi

# kerbrute publishes prebuilt binaries for linux_386 and linux_amd64 only — there is no
# arm64 release. On arm64 it is skipped rather than pulling the Go toolchain into the
# image for one tool; `pwner doctor` will report it missing, and only kerbrute_userenum
# needs it.
ARG KERBRUTE_VERSION=1.0.3
RUN set -eux; \
    if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        curl -fsSL -o /usr/local/bin/kerbrute \
          "https://github.com/ropnop/kerbrute/releases/download/v${KERBRUTE_VERSION}/kerbrute_linux_amd64"; \
        chmod +x /usr/local/bin/kerbrute; \
    else \
        echo "kerbrute: no prebuilt binary for this architecture, skipping"; \
    fi

WORKDIR /app
# Copy the metadata first so the dependency layer survives a source-only change.
COPY pyproject.toml README.md LICENSE requirements.txt ./
COPY pwner ./pwner
RUN pip install --no-cache-dir .

# Templates are ~14k files and a slow first run; bake them in. Non-fatal so the image
# still builds without network access to the template repo.
RUN nuclei -update-templates -duc 2>/dev/null || \
    echo "nuclei templates not fetched at build time — run 'nuclei -update-templates' once"

# Fail the build if a tool pwner expects did not land. `doctor` exits non-zero only when
# a CORE dependency (nmap) is missing, so print the full report either way.
RUN pwner doctor

ENTRYPOINT ["pwner"]
CMD []
