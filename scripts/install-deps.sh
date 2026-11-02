#!/usr/bin/env bash
# Install the external binaries pwner drives.
#
#   ./scripts/install-deps.sh              # install what is missing
#   ./scripts/install-deps.sh --dry-run    # just print what it would run
#   ./scripts/install-deps.sh --core       # nmap only (the single hard requirement)
#
# nmap is the only hard requirement; everything else just enables more tools, so a
# failure on an optional one is reported and skipped rather than aborting the run.
# `pwner doctor` reports the same set at any time, and is the authority on what is
# missing — this script is the automation on top of it.

set -uo pipefail

DRY=0
CORE_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --dry-run|-n) DRY=1 ;;
        --core)       CORE_ONLY=1 ;;
        -h|--help)    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

run() {
    if [ "$DRY" = 1 ]; then printf '  would run: %s\n' "$*"; return 0; fi
    printf '  $ %s\n' "$*"
    "$@"
}

have() { command -v "$1" >/dev/null 2>&1; }

# ── which package manager are we on ──────────────────────────────────────────
PM=""
for m in brew apt pacman dnf; do have "$m" && { PM="$m"; break; }; done
if [ -z "$PM" ]; then
    echo "no supported package manager found (brew/apt/pacman/dnf)." >&2
    echo "Install nmap by hand, then run: pwner doctor" >&2
    exit 1
fi

pm_install() {
    case "$PM" in
        brew)   run brew install "$@" ;;
        apt)    run sudo apt-get install -y "$@" ;;
        pacman) run sudo pacman -S --needed --noconfirm "$@" ;;
        dnf)    run sudo dnf install -y "$@" ;;
    esac
}

echo "package manager: $PM"
[ "$DRY" = 1 ] && echo "(dry run — nothing will be installed)"
echo

# ── nmap: required ───────────────────────────────────────────────────────────
echo "== required =="
if have nmap; then
    echo "  nmap already installed"
else
    pm_install nmap || { echo "  !! could not install nmap — pwner cannot scan without it" >&2; exit 1; }
fi

if [ "$CORE_ONLY" = 1 ]; then
    echo; echo "core only — stopping here. Run 'pwner doctor' to see what else is available."
    exit 0
fi

# ── OS packages, where each distro actually has them ─────────────────────────
# Package names differ per distro, and some tools are simply not packaged
# everywhere: nuclei is absent from Debian and Arch's own repos, and exploitdb is
# absent from Debian and Fedora. Those fall through to the language-specific or
# manual routes below rather than failing.
echo; echo "== optional, from $PM =="

os_pkg() {  # os_pkg <binary> <brew> <apt> <pacman> <dnf>
    local bin="$1" pkg=""
    case "$PM" in
        brew) pkg="$2" ;; apt) pkg="$3" ;; pacman) pkg="$4" ;; dnf) pkg="$5" ;;
    esac
    if have "$bin"; then echo "  $bin already installed"; return; fi
    if [ -z "$pkg" ] || [ "$pkg" = "-" ]; then
        echo "  $bin: not packaged for $PM — see 'pwner doctor' for the manual route"
        return
    fi
    pm_install "$pkg" || echo "  !! $bin failed to install (optional, continuing)"
}

#       binary        brew       apt       pacman     dnf
os_pkg hydra          hydra      hydra     hydra      hydra
os_pkg snmpwalk       net-snmp   snmp      net-snmp   net-snmp-utils
os_pkg hashcat        hashcat    hashcat   hashcat    hashcat
os_pkg nuclei         nuclei     -         -          nuclei
os_pkg searchsploit   exploitdb  -         exploitdb  -

# ── Python-ecosystem tools, each in its own venv via pipx ────────────────────
echo; echo "== optional, from pipx =="
if ! have pipx; then
    echo "  pipx missing — installing it first"
    case "$PM" in
        brew) pm_install pipx ;;
        apt)  pm_install pipx ;;
        pacman) pm_install python-pipx ;;
        dnf)  pm_install pipx ;;
    esac
fi

if have pipx; then
    # netexec is NOT on PyPI; it has to come from the repository.
    pipx_install() {  # pipx_install <label> <spec> [probe-binary ...]
        local label="$1" spec="$2"; shift 2
        local probes=("$@"); [ ${#probes[@]} -eq 0 ] && probes=("$label")
        for b in "${probes[@]}"; do
            if have "$b"; then echo "  $label already installed"; return; fi
        done
        run pipx install "$spec" || echo "  !! $label failed to install (optional, continuing)"
    }
    # impacket ships no binary named "impacket" — probe one of the scripts it installs.
    pipx_install impacket           impacket            impacket-GetNPUsers GetNPUsers.py
    pipx_install certipy            certipy-ad
    pipx_install bloodhound-python  bloodhound
    pipx_install netexec            "git+https://github.com/Pennyw0rth/NetExec"
else
    echo "  pipx unavailable — skipping impacket/certipy/bloodhound/netexec"
fi

# ── things with no package anywhere ──────────────────────────────────────────
echo; echo "== manual =="
if have kerbrute; then
    echo "  kerbrute already installed"
else
    echo "  kerbrute: upstream publishes linux_386 and linux_amd64 only (no arm64, no macOS arm)."
    echo "    amd64 Linux: download from https://github.com/ropnop/kerbrute/releases"
    echo "    anything else: go install github.com/ropnop/kerbrute@latest"
fi
if have nuclei && [ "$DRY" = 0 ]; then
    echo "  fetching nuclei templates (one time, ~14k files)"
    run nuclei -update-templates -duc || echo "  !! template fetch failed; run 'nuclei -update-templates' yourself"
fi

echo
echo "done. Verify with:  pwner doctor"
