#!/usr/bin/env bash
# =============================================================================
# install-laurel.sh -- Build and install LAUREL from source
#
# Follows the official installation guide:
#   https://github.com/threathunters-io/laurel/blob/master/INSTALL.md
#
# What this script does:
#   1. Installs build dependencies (Rust toolchain, clang, libacl headers, git)
#   2. Clones the LAUREL repository and builds a release binary
#   3. Creates the _laurel system user and log directory
#   4. Installs the binary to /usr/local/sbin/laurel
#   5. Writes the default config to /etc/laurel/config.toml
#   6. Registers LAUREL as an auditd plugin
#   7. Signals auditd to pick up the new plugin
#
# Usage:
#   sudo bash /usr/local/bin/install-laurel.sh
#
# Requirements:
#   - Root privileges
#   - Internet access (to clone the repo and install packages)
#   - auditd must be installed and running
# =============================================================================

set -euo pipefail

# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #

LAUREL_REPO="https://github.com/threathunters-io/laurel.git"
LAUREL_USER="_laurel"
LAUREL_BIN="/usr/local/sbin/laurel"
LAUREL_CONF_DIR="/etc/laurel"
LAUREL_CONF="${LAUREL_CONF_DIR}/config.toml"
LAUREL_LOG_DIR="/var/log/laurel"
BUILD_DIR=$(mktemp -d /tmp/laurel-build-XXXX)

# Detect auditd version to choose the correct plugin directory.
# auditd 3.x uses /etc/audit/plugins.d/; auditd 2.x uses /etc/audisp/plugins.d/.
AUDITD_MAJOR=$(auditctl -v 2>/dev/null | grep -oP '\d+' | head -1 || echo "3")
if (( AUDITD_MAJOR >= 3 )); then
    PLUGIN_DIR="/etc/audit/plugins.d"
else
    PLUGIN_DIR="/etc/audisp/plugins.d"
fi
PLUGIN_CONF="${PLUGIN_DIR}/laurel.conf"

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
die()   { echo -e "${RED}[FATAL]${NC} $*" >&2; exit 1; }

cleanup() {
    if [[ -d "$BUILD_DIR" ]]; then
        info "Cleaning up build directory ${BUILD_DIR}"
        rm -rf "$BUILD_DIR"
    fi
}
trap cleanup EXIT

# --------------------------------------------------------------------------- #
# Pre-flight checks
# --------------------------------------------------------------------------- #

[[ $EUID -eq 0 ]] || die "This script must be run as root."
command -v auditctl >/dev/null 2>&1 || die "auditd does not appear to be installed."

echo -e "${BOLD}================================================================${NC}"
echo -e "${BOLD}  LAUREL -- Linux Audit Usable Real-time Event Logging${NC}"
echo -e "${BOLD}  Build-from-source installer${NC}"
echo -e "${BOLD}================================================================${NC}"
echo

# --------------------------------------------------------------------------- #
# Step 1 -- Install build dependencies
# --------------------------------------------------------------------------- #

info "Installing build dependencies ..."

if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq git clang libacl1-dev pkg-config curl >/dev/null
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q git clang libacl-devel pkg-config curl
elif command -v yum >/dev/null 2>&1; then
    yum install -y -q git clang libacl-devel pkg-config curl
else
    die "Unsupported package manager. Install git, clang, libacl-dev, and pkg-config manually."
fi

# Install Rust toolchain if not present.
if ! command -v cargo >/dev/null 2>&1; then
    info "Rust toolchain not found -- installing via rustup ..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
    # shellcheck disable=SC1091
    source "${HOME}/.cargo/env"
fi

ok "Build dependencies ready  (rustc $(rustc --version | awk '{print $2}'))"

# --------------------------------------------------------------------------- #
# Step 2 -- Clone and build
# --------------------------------------------------------------------------- #

info "Cloning LAUREL repository into ${BUILD_DIR} ..."
git clone --quiet --depth 1 "$LAUREL_REPO" "$BUILD_DIR"

info "Building release binary (this may take a few minutes) ..."
cd "$BUILD_DIR"
cargo build --release --quiet 2>&1

BUILT_BIN="${BUILD_DIR}/target/release/laurel"
[[ -x "$BUILT_BIN" ]] || die "Build failed -- ${BUILT_BIN} not found."
ok "Build succeeded  ($(file -b "$BUILT_BIN" | cut -d, -f1-2))"

# --------------------------------------------------------------------------- #
# Step 3 -- Create system user and directories
# --------------------------------------------------------------------------- #

if id "$LAUREL_USER" >/dev/null 2>&1; then
    ok "System user '${LAUREL_USER}' already exists"
else
    info "Creating system user '${LAUREL_USER}' ..."
    useradd --system --home-dir "$LAUREL_LOG_DIR" --create-home "$LAUREL_USER"
    ok "Created user '${LAUREL_USER}'"
fi

# Ensure the log directory exists with correct ownership.
install -d -o "$LAUREL_USER" -g "$LAUREL_USER" -m 0750 "$LAUREL_LOG_DIR"

# --------------------------------------------------------------------------- #
# Step 4 -- Install binary
# --------------------------------------------------------------------------- #

info "Installing binary to ${LAUREL_BIN} ..."
install -m 0755 "$BUILT_BIN" "$LAUREL_BIN"
ok "Installed ${LAUREL_BIN}  ($(${LAUREL_BIN} --version 2>&1 || echo 'version unknown'))"

# --------------------------------------------------------------------------- #
# Step 5 -- Write default configuration
# --------------------------------------------------------------------------- #

install -d -m 0755 "$LAUREL_CONF_DIR"

if [[ -f "$LAUREL_CONF" ]]; then
    info "Existing config found at ${LAUREL_CONF} -- backing up"
    cp -a "$LAUREL_CONF" "${LAUREL_CONF}.bak.$(date +%s)"
fi

info "Writing default configuration to ${LAUREL_CONF} ..."
cat > "$LAUREL_CONF" <<'TOML'
# LAUREL default configuration
# See https://github.com/threathunters-io/laurel for full documentation.

# Write log files relative to this directory
directory = "/var/log/laurel"

# Drop privileges from root to this user
user = "_laurel"

# Periodical status information printed to syslog (seconds, 0 = disabled)
statusreport-period = 0

# Read audit events from stdin (auditd plugin mode)
input = "stdin"

[auditlog]
file = "audit.log"
# Rotate when log file reaches this size (bytes)
size = 5000000
# Number of rotated generations to keep
generations = 10

[state]
file = "state"
generations = 0
max-age = 60

[transform]
# Output EXECVE arguments as a JSON array ("array"), a concatenated
# string ("string"), or both ([ "array", "string" ]).
execve-argv = [ "array" ]

[translate]
# Translate numeric arch/syscall/sockaddr values (like auditd log_format=ENRICHED)
universal = false
# Translate numeric UID/GID values to names
user-db = false
# Drop raw numeric values when translated
drop-raw = false

[enrich]
# Add context (event-id, comm, exe, ppid) for process-id fields
pid = true
# Environment variables captured for every EXECVE event
execve-env = [ "LD_PRELOAD", "LD_LIBRARY_PATH" ]
# Add container context to SYSCALL-based events
container = true
# Deprecated top-level CONTAINER_INFO record
container_info = false
# Add systemd cgroup information for service processes
systemd = true
# Add script context to SYSCALL execve events
script = true
# Add supplementary groups for the UID
user-groups = true

[label-process]
# Attach labels from audit keys to the originating process
label-keys = [ "software_mgmt" ]
propagate-labels = [ "software_mgmt" ]

[filter]
# Discard events without any audit key attached
filter-null-keys = false
# What to do with filtered events: "drop" or "log"
filter-action = "drop"
TOML
ok "Configuration written to ${LAUREL_CONF}"

# --------------------------------------------------------------------------- #
# Step 6 -- Register as auditd plugin
# --------------------------------------------------------------------------- #

install -d -m 0755 "$PLUGIN_DIR"

info "Writing auditd plugin config to ${PLUGIN_CONF} ..."
cat > "$PLUGIN_CONF" <<PLUGIN
active = yes
direction = out
type = always
format = string
path = ${LAUREL_BIN}
args = --config ${LAUREL_CONF}
PLUGIN
ok "Plugin registered in ${PLUGIN_CONF}"

# --------------------------------------------------------------------------- #
# Step 7 -- Reload auditd and verify
# --------------------------------------------------------------------------- #

info "Signalling auditd to reload configuration ..."
pkill -HUP auditd || true

# Give auditd a moment to spawn the plugin process.
sleep 2

echo
echo -e "${BOLD}================================================================${NC}"
if pgrep -x laurel >/dev/null 2>&1; then
    LAUREL_PID=$(pgrep -x laurel | head -1)
    ok "LAUREL is running  (pid ${LAUREL_PID})"
    echo -e "  binary  : ${LAUREL_BIN}"
    echo -e "  config  : ${LAUREL_CONF}"
    echo -e "  log dir : ${LAUREL_LOG_DIR}"
    echo -e "  plugin  : ${PLUGIN_CONF}"
else
    echo -e "${RED}[WARN]${NC}  LAUREL process not detected yet."
    echo "  This may be normal if auditd takes longer to spawn plugins."
    echo "  Verify manually with:  pgrep -a laurel"
    echo "  Check auditd status :  systemctl status auditd"
fi
echo -e "${BOLD}================================================================${NC}"
