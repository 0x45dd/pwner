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
have_any() { for b in "$@"; do have "$b" && return 0; done; return 1; }

# ── which package manager are we on ──────────────────────────────────────────
# Kali is treated as its own ecosystem rather than as Debian: it packages nuclei,
# exploitdb, impacket, netexec and certipy, which Debian does not, and ships most of
# them already installed. On Kali this script usually has nothing left to do.
OS_RELEASE="${OS_RELEASE:-/etc/os-release}"   # overridable so the Kali path is testable
is_kali() {
    [ -r "$OS_RELEASE" ] || return 1
    # shellcheck disable=SC1090
    ( . "$OS_RELEASE" 2>/dev/null; [ "${ID:-}" = "kali" ] )
}

PM=""
for m in brew apt pacman dnf; do have "$m" && { PM="$m"; break; }; done
if [ "$PM" = "apt" ] && is_kali; then PM="kali"; fi
if [ -z "$PM" ]; then
    echo "no supported package manager found (brew/apt/pacman/dnf)." >&2
    echo "Install nmap by hand, then run: pwner doctor" >&2
    exit 1
fi

pm_install() {
    case "$PM" in
        brew)       run brew install "$@" ;;
        apt|kali)   run sudo apt-get install -y "$@" ;;
        pacman)     run sudo pacman -S --needed --noconfirm "$@" ;;
        dnf)        run sudo dnf install -y "$@" ;;
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

os_pkg() {  # os_pkg <binary> <brew> <apt> <kali> <pacman> <dnf>
    local spec="$1" pkg="" label="${1%%|*}"
    case "$PM" in
        brew) pkg="$2" ;; apt) pkg="$3" ;; kali) pkg="$4" ;;
        pacman) pkg="$5" ;; dnf) pkg="$6" ;;
    esac
    # The first field may list alternatives separated by "|" — netexec answers to nxc
    # too, and finding either one means there is nothing to install.
    local IFS='|'
    # shellcheck disable=SC2086
    if have_any $spec; then echo "  $label already installed"; return; fi
    unset IFS
    local bin="$label"
    if [ -z "$pkg" ] || [ "$pkg" = "-" ]; then
        echo "  $bin: not packaged for $PM — see 'pwner doctor' for the manual route"
        return
    fi
    pm_install "$pkg" || echo "  !! $bin failed to install (optional, continuing)"
}

#       binary        brew       apt       kali       pacman     dnf
os_pkg hydra          hydra      hydra     hydra      hydra      hydra
os_pkg snmpwalk       net-snmp   snmp      snmp       net-snmp   net-snmp-utils
os_pkg hashcat        hashcat    hashcat   hashcat    hashcat    hashcat
os_pkg nuclei         nuclei     -         nuclei     -          nuclei
os_pkg searchsploit   exploitdb  -         exploitdb  exploitdb  -
os_pkg dirsearch      -          dirsearch dirsearch  -          -

# Kali packages the AD toolchain the other distros leave to pipx, and ships most of it
# preinstalled. Taking it from apt here means the pipx block below finds the binaries
# already on PATH and skips, instead of building a second copy in its own venv.
if [ "$PM" = "kali" ]; then
    echo; echo "== optional, from kali's own repository =="
    os_pkg 'impacket-GetNPUsers|GetNPUsers.py'  -  -  impacket-scripts  -  -
    os_pkg 'netexec|nxc|crackmapexec'  -  -  netexec  -  -
    os_pkg 'certipy-ad|certipy'  -  -  certipy-ad  -  -
    os_pkg bloodhound-python  -  -  bloodhound.py  -  -
fi

# ── Python-ecosystem tools, each in its own venv via pipx ────────────────────
echo; echo "== optional, from pipx =="

# Nothing to do if the OS already provided all four — which is the normal case on Kali.
# Bootstrapping pipx to then install nothing is pure cost, so check first.
need_pipx=0
have_any impacket-GetNPUsers GetNPUsers.py            || need_pipx=1
have_any certipy certipy-ad                           || need_pipx=1
have_any bloodhound-python                            || need_pipx=1
have_any netexec nxc crackmapexec                     || need_pipx=1
have_any dirsearch                                    || need_pipx=1

if [ "$need_pipx" = 0 ]; then
    echo "  impacket, certipy, bloodhound-python, netexec and dirsearch are already installed"
elif ! have pipx; then
    echo "  pipx missing — installing it first"
    case "$PM" in
        brew|apt|kali) pm_install pipx ;;
        pacman)        pm_install python-pipx ;;
        dnf)           pm_install pipx ;;
    esac
fi

if [ "$need_pipx" = 0 ]; then
    :   # the OS package manager already covered all of them
elif have pipx; then
    # netexec is NOT on PyPI; it has to come from the repository.
    pipx_install() {  # pipx_install <label> <spec> [probe-binary ...]
        local label="$1" spec="$2"; shift 2
        local probes=("$@"); [ ${#probes[@]} -eq 0 ] && probes=("$label")
        for b in "${probes[@]}"; do
            if have "$b"; then echo "  $label already installed"; return; fi
        done
        run pipx install "$spec" || echo "  !! $label failed to install (optional, continuing)"
    }
    # Probe every name a working install can go by, or this builds a second copy of a
    # tool that is already on PATH: impacket ships no binary called "impacket", Kali's
    # certipy-ad installs /usr/bin/certipy-ad, and netexec answers to nxc as well.
    pipx_install impacket           impacket            impacket-GetNPUsers GetNPUsers.py
    pipx_install certipy            certipy-ad          certipy certipy-ad
    pipx_install bloodhound-python  bloodhound
    pipx_install netexec            "git+https://github.com/Pennyw0rth/NetExec" netexec nxc crackmapexec
    pipx_install dirsearch          dirsearch
else
    echo "  pipx unavailable — skipping impacket/certipy/bloodhound/netexec/dirsearch"
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
    # No -duc here: it reads as "skip the update-check nag" but also suppresses the
    # template download, so the command exits 0 having fetched nothing. Measured in a
    # clean container: with -duc, 0 templates; without it, 14104.
    echo "  fetching nuclei templates (one time, ~14k files)"
    run nuclei -update-templates || echo "  !! template fetch failed; run 'nuclei -update-templates' yourself"
fi

echo
echo "done. Verify with:  pwner doctor"
