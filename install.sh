#!/usr/bin/env bash
# Install pwner so that typing `pwner` in any directory opens a session.
#
#   ./install.sh                     # from a clone
#   curl -fsSL https://raw.githubusercontent.com/0x45dd/pwner/main/install.sh | bash
#
#   ./install.sh --with-tools        # also install nmap and the optional scanners
#   ./install.sh --no-path           # do not touch any shell startup file
#   ./install.sh --uninstall         # remove what this script installed
#
# What it does, and nothing else:
#   1. finds a Python 3.10+ interpreter
#   2. builds a virtualenv under ~/.local/share/pwner  (your system Python is untouched)
#   3. installs pwner into it, editable, so `git pull` in the source tree updates it
#   4. symlinks ~/.local/bin/pwner at that venv
#   5. if ~/.local/bin is not on your PATH, adds it to your shell's startup file,
#      inside a marked block that --uninstall removes again
#
# It never runs sudo on its own. --with-tools does, and tells you before it does.

set -euo pipefail

readonly MIN_PY_MINOR=10
readonly REPO_URL="https://github.com/0x45dd/pwner.git"
readonly MARK_BEGIN="# >>> pwner >>>"
readonly MARK_END="# <<< pwner <<<"

PWNER_HOME="${PWNER_HOME:-$HOME/.local/share/pwner}"
BIN_DIR="${PWNER_BIN_DIR:-$HOME/.local/bin}"
VENV="$PWNER_HOME/venv"
LINK="$BIN_DIR/pwner"

WITH_TOOLS=0
TOUCH_PATH=1
UNINSTALL=0

# ── output ───────────────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    B=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; R=$'\033[0m'
else
    B=""; DIM=""; RED=""; YEL=""; GRN=""; R=""
fi
step() { printf '%s==>%s %s\n' "$B" "$R" "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%swarning:%s %s\n' "$YEL" "$R" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$RED" "$R" "$*" >&2; exit 1; }

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

for arg in "$@"; do
    case "$arg" in
        --with-tools) WITH_TOOLS=1 ;;
        --no-path)    TOUCH_PATH=0 ;;
        --uninstall)  UNINSTALL=1 ;;
        -h|--help)    usage ;;
        *) die "unknown option: $arg   (try --help)" ;;
    esac
done

# ── uninstall ────────────────────────────────────────────────────────────────
remove_path_block() {
    local rc="$1"
    [ -f "$rc" ] || return 0
    grep -qF "$MARK_BEGIN" "$rc" || return 0
    cp "$rc" "$rc.pwner-backup.$(date +%Y%m%d%H%M%S)"
    # delete the marked block only; everything else in the file is left alone
    awk -v a="$MARK_BEGIN" -v b="$MARK_END" '
        index($0,a){skip=1} !skip{print} index($0,b){skip=0}' "$rc" > "$rc.pwner-tmp"
    mv "$rc.pwner-tmp" "$rc"
    info "removed the PATH block from $rc (backup kept alongside it)"
}

if [ "$UNINSTALL" = 1 ]; then
    step "Uninstalling pwner"
    if [ -L "$LINK" ]; then rm -f "$LINK"; info "removed $LINK"; fi
    if [ -d "$VENV" ]; then rm -rf "$VENV"; info "removed $VENV"; fi
    for rc in "${ZDOTDIR:-$HOME}/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" \
              "$HOME/.profile" "$HOME/.config/fish/config.fish"; do
        remove_path_block "$rc"
    done
    if [ -d "$PWNER_HOME/src" ]; then
        info "the source clone at $PWNER_HOME/src was left in place"
        info "delete it yourself if you want it gone:  rm -rf $PWNER_HOME/src"
    fi
    info "your settings at ~/.config/pwner and saved sessions were NOT touched"
    printf '%sdone.%s\n' "$GRN" "$R"
    exit 0
fi

# ── preflight ────────────────────────────────────────────────────────────────
step "Checking this machine"

case "$(uname -s)" in
    Linux|Darwin) : ;;
    *) die "unsupported platform: $(uname -s). pwner runs on Linux and macOS." ;;
esac

if [ "$(id -u)" = 0 ] && [ -z "${PWNER_ALLOW_ROOT:-}" ]; then
    die "do not run this as root: it would install into /root and leave the symlink
       unusable for your own account. Run it as yourself; --with-tools asks for sudo
       only where a package manager needs it."
fi

# Pick the newest Python we can find that is new enough.
PY=""
for cand in python3.14 python3.13 python3.12 python3.11 python3.10 python3 python; do
    command -v "$cand" >/dev/null 2>&1 || continue
    if "$cand" -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, $MIN_PY_MINOR) else 1)" 2>/dev/null; then
        PY="$cand"; break
    fi
done
[ -n "$PY" ] || die "no Python 3.$MIN_PY_MINOR or newer found.
       Debian/Ubuntu/Kali:  sudo apt install python3 python3-venv
       Fedora:              sudo dnf install python3
       Arch:                sudo pacman -S python
       macOS:               brew install python"
info "python: $("$PY" -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])') ($(command -v "$PY"))"

# ── where the source lives ───────────────────────────────────────────────────
SRC=""
# $0 is unreliable under `curl | bash`, so only trust it when it is a real file.
if [ -f "${BASH_SOURCE[0]:-}" ]; then
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$here/pyproject.toml" ] && [ -d "$here/pwner" ]; then
        SRC="$here"
    fi
fi

if [ -n "$SRC" ]; then
    info "source: $SRC (running from a clone)"
else
    command -v git >/dev/null 2>&1 || die "git is needed to fetch the source.
       Debian/Ubuntu/Kali: sudo apt install git   ·   macOS: xcode-select --install"
    SRC="$PWNER_HOME/src"
    if [ -d "$SRC/.git" ]; then
        step "Updating the existing source at $SRC"
        git -C "$SRC" fetch --quiet origin
        if ! git -C "$SRC" diff --quiet || ! git -C "$SRC" diff --cached --quiet; then
            warn "local changes in $SRC — leaving them alone and skipping the update"
        else
            git -C "$SRC" pull --ff-only --quiet
            info "now at $(git -C "$SRC" log --oneline -1)"
        fi
    else
        step "Fetching the source"
        mkdir -p "$(dirname "$SRC")"
        git clone --depth 1 --quiet "$REPO_URL" "$SRC"
        info "cloned to $SRC"
    fi
fi

# ── virtualenv ───────────────────────────────────────────────────────────────
step "Building an isolated environment"
info "at $VENV"
mkdir -p "$PWNER_HOME"
if [ ! -x "$VENV/bin/python" ]; then
    VENV_LOG="$(mktemp "${TMPDIR:-/tmp}/pwner-venv.XXXXXX")"
    if ! "$PY" -m venv "$VENV" >"$VENV_LOG" 2>&1; then
        printf '%s\n' "$DIM--- python said ---$R" >&2
        cat "$VENV_LOG" >&2
        rm -f "$VENV_LOG"
        rm -rf "$VENV"
        die "could not create a virtualenv (python's own error is above).
       On Debian, Ubuntu and Kali the venv module ships separately:
         sudo apt install python3-venv
       Then run this script again."
    fi
    rm -f "$VENV_LOG"
else
    info "reusing the existing environment"
fi

step "Installing pwner"
# Keep the build chatter out of the way: pip --quiet still lets setuptools warnings
# through, and a clean run should say nothing. On failure the whole log is printed,
# because that is the moment you need it.
PIP_LOG="$(mktemp "${TMPDIR:-/tmp}/pwner-pip.XXXXXX")"
trap 'rm -f "$PIP_LOG"' EXIT

"$VENV/bin/python" -m pip install --upgrade pip >"$PIP_LOG" 2>&1 || \
    warn "could not upgrade pip inside the venv; continuing with the version it has"

# --editable so that a later `git pull` in the source tree updates the command too.
if ! "$VENV/bin/python" -m pip install --editable "$SRC" >"$PIP_LOG" 2>&1; then
    printf '%s\n' "$DIM--- pip output ---$R" >&2
    cat "$PIP_LOG" >&2
    die "pip could not install pwner from $SRC (full output above)."
fi
info "$("$VENV/bin/pwner" --version 2>/dev/null || echo 'pwner installed')"

# ── the command itself ───────────────────────────────────────────────────────
step "Putting pwner on your PATH"
mkdir -p "$BIN_DIR"
if [ -e "$LINK" ] && [ ! -L "$LINK" ]; then
    die "$LINK already exists and is not a symlink.
       Move it aside and run this again, so nothing of yours is overwritten."
fi
ln -sfn "$VENV/bin/pwner" "$LINK"
info "$LINK -> $VENV/bin/pwner"

on_path() { case ":${PATH:-}:" in *":$BIN_DIR:"*) return 0 ;; *) return 1 ;; esac; }

shell_name() {
    # $SHELL is the usual answer, but it is empty under some service managers and
    # inside containers. Fall back to the login shell on record, then to whichever
    # startup file already exists.
    local s="${SHELL:-}"
    if [ -z "$s" ] && command -v getent >/dev/null 2>&1; then
        s="$(getent passwd "$(id -un)" 2>/dev/null | awk -F: '{print $NF}')"
    fi
    if [ -z "$s" ]; then
        if   [ -f "${ZDOTDIR:-$HOME}/.zshrc" ]; then s="zsh"
        elif [ -f "$HOME/.bashrc" ] || [ -f "$HOME/.bash_profile" ]; then s="bash"
        fi
    fi
    basename "$s" 2>/dev/null || printf ''
}

startup_file() {
    case "$(shell_name)" in
        zsh)  printf '%s\n' "${ZDOTDIR:-$HOME}/.zshrc" ;;
        bash) if [ "$(uname -s)" = "Darwin" ]; then printf '%s\n' "$HOME/.bash_profile"
              else printf '%s\n' "$HOME/.bashrc"; fi ;;
        fish) printf '%s\n' "$HOME/.config/fish/config.fish" ;;
        *)    printf '%s\n' "" ;;
    esac
}

PATH_NOTE=""
if on_path; then
    info "$BIN_DIR is already on your PATH"
elif [ "$TOUCH_PATH" = 0 ]; then
    PATH_NOTE="add $BIN_DIR to your PATH yourself (--no-path was given)"
else
    RC="$(startup_file)"
    if [ -z "$RC" ]; then
        PATH_NOTE="could not tell which shell you use; add $BIN_DIR to your PATH by hand"
    elif [ -f "$RC" ] && grep -qF "$MARK_BEGIN" "$RC"; then
        info "$RC already has the PATH line"
        PATH_NOTE="open a new terminal, or run:  source $RC"
    else
        mkdir -p "$(dirname "$RC")"
        [ -f "$RC" ] && cp "$RC" "$RC.pwner-backup.$(date +%Y%m%d%H%M%S)"
        {
            printf '\n%s\n' "$MARK_BEGIN"
            if [ "$(shell_name)" = "fish" ]; then
                printf 'fish_add_path %s\n' "$BIN_DIR"
            else
                # SC2016 is the point here: $PATH must land in the file literally so the
                # shell expands it at startup, not this script at install time.
                # shellcheck disable=SC2016
                printf 'export PATH="%s:$PATH"\n' "$BIN_DIR"
            fi
            printf '%s\n' "$MARK_END"
        } >> "$RC"
        info "added $BIN_DIR to $RC"
        PATH_NOTE="open a new terminal, or run:  source $RC"
    fi
fi

# ── external scanners ────────────────────────────────────────────────────────
if [ "$WITH_TOOLS" = 1 ]; then
    step "Installing the external tools pwner drives"
    if [ -x "$SRC/scripts/install-deps.sh" ]; then
        info "this calls your package manager and will ask for sudo"
        "$SRC/scripts/install-deps.sh" || warn "some optional tools did not install; pwner doctor will list them"
    else
        warn "scripts/install-deps.sh not found in $SRC — skipping"
    fi
fi

# ── verify ───────────────────────────────────────────────────────────────────
step "Checking the install"
if ! "$VENV/bin/pwner" --version >/dev/null 2>&1; then
    die "pwner was installed but will not run. Try: $VENV/bin/pwner --version"
fi
if "$VENV/bin/pwner" doctor >/dev/null 2>&1; then
    info "nmap is present, so pwner can scan"
else
    warn "nmap is missing — it is the one hard requirement."
    warn "run:  $SRC/install.sh --with-tools   (or install nmap yourself, then: pwner doctor)"
fi

printf '\n%sInstalled.%s\n\n' "$GRN" "$R"
if [ -n "$PATH_NOTE" ]; then
    printf '  %s\n\n' "$PATH_NOTE"
fi
cat <<EOF
  pwner                     open a session (first run asks for a provider and key)
  pwner chat 10.0.0.5       start with a target
  pwner scan 10.0.0.5       one-shot agentic scan, no TUI
  pwner scan 10.0.0.5 --no-ai   deterministic, needs no model
  pwner doctor              what is installed and what each tool enables

  ${DIM}source     $SRC
  update     git -C "$SRC" pull
  remove     $SRC/install.sh --uninstall${R}

  Authorized testing only: pwner sends real traffic to the hosts you name and,
  with your approval, breaks into them. Only point it at systems you own or have
  written permission to test.
EOF
