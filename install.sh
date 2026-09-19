#!/usr/bin/env sh
# install.sh — one-liner installer for system-suite
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/hamimLohani/system_suite/main/install.sh | sh
#
# Options (env vars):
#   SYSTEM_SUITE_VERSION     — specific version/tag, e.g. "v1.3.0" (default: latest release or main)
#   SYSTEM_SUITE_INSTALL_DIR — install directory (default: /usr/local/bin, fallback ~/.local/bin)
#   SYSTEM_SUITE_NO_SUDO     — set to "1" to never use sudo (forces ~/.local/bin)

set -e

REPO="hamimLohani/system_suite"
BINARY="system-suite"
VERSION="${SYSTEM_SUITE_VERSION:-}"
NO_SUDO="${SYSTEM_SUITE_NO_SUDO:-0}"
RAW_BASE="https://raw.githubusercontent.com/${REPO}"

# ── Color helpers ─────────────────────────────────────────────────────────────
if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
  BOLD='\033[1m'
  GREEN='\033[32m'
  YELLOW='\033[33m'
  RED='\033[31m'
  CYAN='\033[36m'
  RESET='\033[0m'
else
  BOLD=''; GREEN=''; YELLOW=''; RED=''; CYAN=''; RESET=''
fi

info()  { printf "${CYAN}  →${RESET} %s\n" "$*"; }
ok()    { printf "${GREEN}  ✓${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}  ⚠${RESET} %s\n" "$*"; }
error() { printf "${RED}  ✗${RESET} %s\n" "$*" >&2; exit 1; }

# ── Detect OS / architecture ──────────────────────────────────────────────────
detect_platform() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "$OS" in
    Linux)  OS="linux"  ;;
    Darwin) OS="darwin" ;;
    FreeBSD|OpenBSD|NetBSD) OS="unix" ;;
    *)      OS="generic" ;;
  esac

  case "$ARCH" in
    x86_64 | amd64)  ARCH="amd64" ;;
    aarch64 | arm64) ARCH="arm64" ;;
    *)               ARCH="generic" ;;
  esac
}

# ── Resolve version ───────────────────────────────────────────────────────────
resolve_version() {
  if [ -n "$VERSION" ]; then
    return
  fi

  info "Detecting latest release..."
  if command -v curl >/dev/null 2>&1; then
    VERSION=$(curl -sSfL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
      | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\(.*\)".*/\1/')
  elif command -v wget >/dev/null 2>&1; then
    VERSION=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
      | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\(.*\)".*/\1/')
  fi

  if [ -z "$VERSION" ]; then
    VERSION="main"
    warn "Could not query GitHub Releases API; installing from ${BOLD}main${RESET} branch."
  fi
}

# ── Choose install directory ──────────────────────────────────────────────────
choose_install_dir() {
  if [ -n "${SYSTEM_SUITE_INSTALL_DIR:-}" ]; then
    INSTALL_DIR="$SYSTEM_SUITE_INSTALL_DIR"
    MAN_DIR="${INSTALL_DIR%/*}/share/man/man1"
    return
  fi

  if [ "$NO_SUDO" = "0" ] && [ -w /usr/local/bin ]; then
    INSTALL_DIR="/usr/local/bin"
    MAN_DIR="/usr/local/share/man/man1"
    USE_SUDO=0
  elif [ "$NO_SUDO" = "0" ] && command -v sudo >/dev/null 2>&1; then
    INSTALL_DIR="/usr/local/bin"
    MAN_DIR="/usr/local/share/man/man1"
    USE_SUDO=1
  else
    INSTALL_DIR="$HOME/.local/bin"
    MAN_DIR="$HOME/.local/share/man/man1"
    USE_SUDO=0
    warn "/usr/local/bin not writable; installing to ${INSTALL_DIR}"
  fi
}

# ── Download and install ──────────────────────────────────────────────────────
download_and_install() {
  TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'system_suite_install')"
  trap 'rm -rf "$TMP_DIR"' EXIT

  info "Downloading ${BOLD}${BINARY}${RESET} (${VERSION})..."

  SCRIPT_URL="${RAW_BASE}/${VERSION}/system_suite.sh"
  MAN_URL="${RAW_BASE}/${VERSION}/man/system-suite.1"
  BASH_COMP_URL="${RAW_BASE}/${VERSION}/completions/system-suite.bash"
  ZSH_COMP_URL="${RAW_BASE}/${VERSION}/completions/system-suite.zsh"

  if command -v curl >/dev/null 2>&1; then
    curl -sSfL "$SCRIPT_URL" -o "$TMP_DIR/$BINARY" || error "Failed to download $SCRIPT_URL"
    curl -sSfL "$MAN_URL" -o "$TMP_DIR/system-suite.1" 2>/dev/null || true
    curl -sSfL "$BASH_COMP_URL" -o "$TMP_DIR/system-suite.bash" 2>/dev/null || true
    curl -sSfL "$ZSH_COMP_URL" -o "$TMP_DIR/system-suite.zsh" 2>/dev/null || true
  else
    wget -qO "$TMP_DIR/$BINARY" "$SCRIPT_URL" || error "Failed to download $SCRIPT_URL"
    wget -qO "$TMP_DIR/system-suite.1" "$MAN_URL" 2>/dev/null || true
    wget -qO "$TMP_DIR/system-suite.bash" "$BASH_COMP_URL" 2>/dev/null || true
    wget -qO "$TMP_DIR/system-suite.zsh" "$ZSH_COMP_URL" 2>/dev/null || true
  fi

  chmod +x "$TMP_DIR/$BINARY"

  # Install executable
  if [ "${USE_SUDO:-0}" = "1" ]; then
    sudo mkdir -p "$INSTALL_DIR"
    sudo mv "$TMP_DIR/$BINARY" "${INSTALL_DIR}/${BINARY}"
  else
    mkdir -p "$INSTALL_DIR"
    mv "$TMP_DIR/$BINARY" "${INSTALL_DIR}/${BINARY}"
  fi

  # Install man page
  if [ -f "$TMP_DIR/system-suite.1" ]; then
    if [ "${USE_SUDO:-0}" = "1" ]; then
      sudo mkdir -p "$MAN_DIR" 2>/dev/null || true
      sudo cp -f "$TMP_DIR/system-suite.1" "${MAN_DIR}/" 2>/dev/null || true
    else
      mkdir -p "$MAN_DIR" 2>/dev/null || true
      cp -f "$TMP_DIR/system-suite.1" "${MAN_DIR}/" 2>/dev/null || true
    fi
  fi
}

# ── Verify ────────────────────────────────────────────────────────────────────
verify() {
  if "${INSTALL_DIR}/${BINARY}" --version >/dev/null 2>&1; then
    INSTALLED_VER=$("${INSTALL_DIR}/${BINARY}" --version 2>&1 | head -1)
    ok "Installed: ${BOLD}${INSTALLED_VER}${RESET}"
    ok "Binary:    ${INSTALL_DIR}/${BINARY}"
  else
    warn "Binary installed at ${INSTALL_DIR}/${BINARY}, but verification failed."
  fi
}

# ── PATH hint ─────────────────────────────────────────────────────────────────
print_path_hint() {
  case ":$PATH:" in
    *":${INSTALL_DIR}:"*) return ;;
  esac

  printf "\n${YELLOW}  ⚠  ${INSTALL_DIR} is not in your PATH.${RESET}\n"
  printf "  Add this to your shell profile (~/.zshrc or ~/.bashrc):\n\n"
  printf "    ${CYAN}export PATH=\"\$PATH:${INSTALL_DIR}\"${RESET}\n\n"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  printf "\n${BOLD}Installing System Suite${RESET}\n\n"

  detect_platform
  resolve_version
  choose_install_dir

  info "Version:     ${VERSION}"
  info "Platform:    ${OS}/${ARCH}"
  info "Install dir: ${INSTALL_DIR}"
  printf "\n"

  download_and_install
  verify
  print_path_hint

  printf "\n${BOLD}${GREEN}Done!${RESET} Run ${CYAN}system-suite --help${RESET} or ${CYAN}system-suite${RESET} to get started.\n\n"
}

main "$@"
