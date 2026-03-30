#!/usr/bin/env bash
# ShareMyBleedings — installer for Linux / WSL (Debian/Ubuntu).
# Usage:  curl -sSL <raw-url>/install.sh | bash
#         or:  ./install.sh
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
say()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

REPO_URL="${BLEEDINGS_REPO:-https://github.com/blacklanternsecurity/MANSPIDER}"
SMB_REPO="${BLEEDINGS_SMB_REPO:-}"  # optional: install smb_bleedings from git too

# --- 1. Sanity checks ---
[[ "$(uname -s)" == "Linux" ]] || die "This installer targets Linux/WSL only."
command -v python3 >/dev/null || die "python3 not found."
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_OK=$(python3 -c 'import sys; print(int(sys.version_info >= (3, 11)))')
[[ "$PY_OK" == "1" ]] || die "Python >= 3.11 required (found $PY_VER)."
say "Python $PY_VER OK"

# --- 2. System dependencies ---
if command -v apt-get >/dev/null; then
    say "Installing system dependencies (sudo apt-get)..."
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends \
        nmap libmagic1 antiword poppler-utils unrtf \
        tesseract-ocr libreoffice-core \
        pipx git ca-certificates
else
    warn "apt-get not found — install nmap/libmagic1/antiword/poppler-utils/unrtf/pipx manually."
fi

# --- 3. Ensure pipx in PATH ---
pipx ensurepath >/dev/null 2>&1 || true
export PATH="$HOME/.local/bin:$PATH"

# --- 4. Install manspider (CLI) ---
if command -v manspider >/dev/null; then
    say "manspider already installed: $(which manspider)"
else
    say "Installing manspider via pipx..."
    pipx install "git+${REPO_URL}"
fi

# --- 5. Install ShareMyBleedings ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/pyproject.toml" ]]; then
    say "Installing ShareMyBleedings from local checkout..."
    pipx install --force "${SCRIPT_DIR}"'[nmap]'
elif [[ -n "$SMB_REPO" ]]; then
    say "Installing ShareMyBleedings from $SMB_REPO..."
    pipx install --force "git+${SMB_REPO}"
else
    die "Run this script from inside the ShareMyBleedings repo, or set BLEEDINGS_SMB_REPO=<git-url>."
fi

# --- 6. Verify ---
if command -v bleedings >/dev/null; then
    say "Installed: $(bleedings --help 2>&1 | head -1 || true)"
    say "Try:  bleedings demo"
else
    warn "bleedings not in PATH — open a new shell or run: source ~/.bashrc"
fi
