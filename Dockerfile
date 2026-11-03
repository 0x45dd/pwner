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
#
# The base is Kali rather than Debian because Kali's repository carries the whole
# toolchain pwner drives — nuclei, exploitdb, impacket, netexec, certipy, bloodhound —
# which Debian's does not. On Debian this file had to fetch a release asset for nuclei,
# clone exploitdb from GitLab and build four pipx venvs; here it is one apt line, and it
# resolves on both amd64 and arm64.
FROM kalilinux/kali-rolling

# One layer for every external tool pwner can shell out to, except kerbrute, which Kali
# does not package either. `snmp` is the package that provides snmpwalk; `exploitdb`
# provides searchsploit and is ~192 MB installed, the largest single item here.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        hydra \
        snmp \
        hashcat \
        nuclei \
        exploitdb \
        impacket-scripts \
        netexec \
        certipy-ad \
        bloodhound.py \
        python3 \
        python3-venv \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# kerbrute publishes prebuilt binaries for linux_386 and linux_amd64 only — there is no
# arm64 release, and it is not in Kali's repository. On arm64 it is skipped rather than
# pulling the Go toolchain into the image for one tool; `pwner doctor` will report it
# missing, and only kerbrute_userenum needs it.
ARG KERBRUTE_VERSION=1.0.3
RUN set -eux; \
    if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        curl -fsSL -o /usr/local/bin/kerbrute \
          "https://github.com/ropnop/kerbrute/releases/download/v${KERBRUTE_VERSION}/kerbrute_linux_amd64"; \
        chmod +x /usr/local/bin/kerbrute; \
    else \
        echo "kerbrute: no prebuilt binary for this architecture, skipping"; \
    fi

# pwner goes in its own venv. Kali's Python is externally managed (PEP 668), so a plain
# `pip install` into the system interpreter is refused — and overriding that would put
# pwner's pinned dependencies in the same place as the system tools' own.
ENV PWNER_VENV=/opt/pwner
RUN python3 -m venv "$PWNER_VENV"
ENV PATH="/opt/pwner/bin:$PATH"

WORKDIR /app
# Copy the metadata first so the dependency layer survives a source-only change.
COPY pyproject.toml README.md LICENSE requirements.txt ./
COPY pwner ./pwner
RUN pip install --no-cache-dir . && rm -rf /root/.cache

# Templates are ~14k files and a slow first run; bake them in. Deliberately NOT passing
# -duc: that flag reads as "disable the update-check nag" but also suppresses the template
# download itself, so the step exits 0 having fetched nothing. Verified in this image:
# with -duc, 0 templates; without it, 14104.
#
# Still non-fatal so the image builds without access to the template repo — but the count
# is asserted below, so a silent miss cannot pass again.
RUN nuclei -update-templates 2>/dev/null || \
    echo "nuclei templates not fetched at build time — run 'nuclei -update-templates' once"

# Fail the build if a tool pwner expects did not land. `doctor` exits non-zero only when
# a CORE dependency (nmap) is missing, so print the full report either way.
RUN pwner doctor

# And assert the templates actually arrived. nuclei_scan is useless without them, and the
# fetch above is allowed to fail quietly, so this is the line that keeps it honest.
RUN n="$(find /root/.local/nuclei-templates -name '*.yaml' 2>/dev/null | wc -l)"; \
    echo "nuclei templates baked in: $n"; \
    [ "$n" -gt 1000 ] || { echo "ERROR: nuclei templates missing from the image" >&2; exit 1; }

ENTRYPOINT ["pwner"]
CMD []
