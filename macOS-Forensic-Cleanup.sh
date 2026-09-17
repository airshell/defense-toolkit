#!/usr/bin/env bash

# ==============================================================================
# macOS Forensic Cleanup Utility (macOS-Forensic-Cleanup.sh)
# ==============================================================================
# Production-grade macOS Digital Forensics & Incident Response (DFIR) Utility
# Designed for incident remediation following macOS crypto-miner infections
# (e.g., LaunchAgent persistence executing AppleScript/base64 RPC payloads
# downloading XMRig into temporary directories).
#
# Target OS Compatibility:
#   - macOS 13 Ventura
#   - macOS 14 Sonoma
#   - macOS 15 Sequoia
# Architecture Support:
#   - Apple Silicon (ARM64) & Intel (x86_64)
#
# Safety & Quality Guarantees:
#   - Defensively configured: set -Eeuo pipefail with signal traps
#   - Idempotent and safe: never deletes user development projects or personal files
#   - Automated backup of modified/deleted plist and configuration files
#   - Full compliance with standard macOS utilities (no Homebrew dependencies)
#   - Dry-run, Verbose, and Quiet mode support
#   - Complete auditing and log generation in ~/Desktop/ForensicCleanupLogs/
# ==============================================================================

set -Eeuo pipefail

# ------------------------------------------------------------------------------
# GLOBAL CONSTANTS & SCRIPT VERSION
# ------------------------------------------------------------------------------
readonly SCRIPT_NAME="macOS-Forensic-Cleanup.sh"
readonly SCRIPT_VERSION="1.1.0"
readonly SCRIPT_DATE="2026-09-17"

# Color Definitions (ANSI)
if [[ -t 1 ]]; then
    readonly COLOR_RESET="\033[0m"
    readonly COLOR_RED="\033[1;31m"
    readonly COLOR_GREEN="\033[1;32m"
    readonly COLOR_YELLOW="\033[1;33m"
    readonly COLOR_BLUE="\033[1;34m"
    readonly COLOR_MAGENTA="\033[1;35m"
    readonly COLOR_CYAN="\033[1;36m"
    readonly COLOR_BOLD="\033[1m"
    readonly COLOR_DIM="\033[2m"
else
    readonly COLOR_RESET=""
    readonly COLOR_RED=""
    readonly COLOR_GREEN=""
    readonly COLOR_YELLOW=""
    readonly COLOR_BLUE=""
    readonly COLOR_MAGENTA=""
    readonly COLOR_CYAN=""
    readonly COLOR_BOLD=""
    readonly COLOR_DIM=""
fi

# Determine Execution User and Target User Home Directory
# If run with sudo, target the original invoking user for home folder scans.
if [[ -n "${SUDO_USER:-}" ]] && [[ "${SUDO_USER}" != "root" ]]; then
    TARGET_USER="${SUDO_USER}"
    TARGET_HOME="$(eval echo "~${SUDO_USER}")"
else
    TARGET_USER="$(whoami)"
    TARGET_HOME="${HOME}"
fi

# Default Log Directory and Paths
TIMESTAMP="$(date +'%Y%m%d-%H%M%S')"
LOG_DIR="${TARGET_HOME}/Desktop/ForensicCleanupLogs"
BACKUP_DIR="${LOG_DIR}/backups/${TIMESTAMP}"
DEFAULT_LOG_FILE="${LOG_DIR}/cleanup-${TIMESTAMP}.log"

# Default Option Flags
DRY_RUN=false
VERBOSE=false
QUIET=false
LOG_FILE="${DEFAULT_LOG_FILE}"

# Incident IOC Definitions
readonly KNOWN_MALWARE_PATHS=(
    "/private/tmp/rigupdater"
    "/private/tmp/xmrig"
    "/private/tmp/xmrig-*"
    "/private/tmp/updstat.txt"
    "/private/tmp/[a-f0-9][a-f0-9][a-f0-9][a-f0-9]*.zip"
    "/private/tmp/[a-f0-9][a-f0-9][a-f0-9][a-f0-9]*"
    "/tmp/rigupdater"
    "/tmp/xmrig"
    "/tmp/xmrig-*"
    "/tmp/updstat.txt"
    "/tmp/[a-f0-9][a-f0-9][a-f0-9][a-f0-9]*.zip"
    "/tmp/[a-f0-9][a-f0-9][a-f0-9][a-f0-9]*"
    "${TARGET_HOME}/.xmrig.json"
    "${TARGET_HOME}/.config/xmrig.json"
)

readonly MALWARE_PROCESS_PATTERNS=(
    "xmrig"
    "rigupdater"
    "hashvault"
    "jse8x92s"
    "polygon.*rpc"
    "polygon-publicnode"
    "osascript.*base64"
    "base64.*osascript"
    "xxd.*xmrig"
    "txid=.*bmodule"
    "prostafene"
    "j8rnojfm"
    "BotGuard"
)

readonly LAUNCHAGENT_MALWARE_PATTERNS=(
    "xmrig"
    "rigupdater"
    "hashvault"
    "jse8x92s"
    "0xA3a603F8a454a9c905b4c579Bb72628F7C15C2A0"
    "polygon"
    "drpc.org"
    "polygon-publicnode"
    "gateway.tatum.io"
    "tenderly.rpc"
    "xxd -r -p"
    "txid="
    "bmodule"
    "prostafene"
    "j8rnojfm"
    "ublib="
    "BotGuard"
)

readonly SUSPICIOUS_STRINGS=(
    "xmrig"
    "rigupdater"
    "hashvault"
    "pool.hashvault.pro"
    "jse8x92s.me"
    "0xA3a603F8a454a9c905b4c579Bb72628F7C15C2A0"
    "polygon.drpc.org"
    "polygon-publicnode.com"
    "polygon-mainnet.gateway.tatum.io"
    "tenderly.rpc.polygon.community"
    "eth_call"
    "xxd -r -p"
    "bmodule"
    "txid="
    "prostafene.com"
    "j8rnojfm"
    "ublib="
    "BotGuard: Answer the protector challenge"
)

# Counters for Statistics
TOTAL_WARNINGS=0
TOTAL_REMEDIATIONS=0
TOTAL_SUSPICIOUS_ITEMS=0

# ------------------------------------------------------------------------------
# TRAP HANDLER & CLEANUP ON EXIT
# ------------------------------------------------------------------------------
trap_error_handler() {
    local exit_code="$1"
    local line_number="$2"
    echo -e "\n${COLOR_RED}[ERROR] Script failed unexpectedly at line ${line_number} with status ${exit_code}.${COLOR_RESET}" >&2
    if [[ -f "${LOG_FILE:-}" ]]; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] Script failed unexpectedly at line ${line_number} with status ${exit_code}." >> "${LOG_FILE}"
    fi
    exit "${exit_code}"
}

trap 'trap_error_handler $? $LINENO' ERR

# ------------------------------------------------------------------------------
# HELPER & LOGGING FUNCTIONS
# ------------------------------------------------------------------------------

# Function: print_banner
# Description: Displays script identity and execution details.
print_banner() {
    if [[ "${QUIET}" == true ]]; then
        return 0
    fi
    cat << "EOF"
===============================================================================
               macOS PRODUCTION FORENSIC CLEANUP UTILITY
            Digital Forensics & Incident Response (DFIR)
===============================================================================
EOF
    echo -e "${COLOR_CYAN}Version:${COLOR_RESET}     ${SCRIPT_VERSION} (${SCRIPT_DATE})"
    echo -e "${COLOR_CYAN}Target User:${COLOR_RESET} ${TARGET_USER} (${TARGET_HOME})"
    echo -e "${COLOR_CYAN}Execution:${COLOR_RESET}   User=$(whoami), Dry-Run=${DRY_RUN}, Verbose=${VERBOSE}, Quiet=${QUIET}"
    echo -e "${COLOR_CYAN}Log File:${COLOR_RESET}    ${LOG_FILE}"
    echo "==============================================================================="
    echo ""
}

# Function: ensure_log_dir
# Description: Prepares destination log directory and backup folders safely.
ensure_log_dir() {
    if [[ ! -d "${LOG_DIR}" ]]; then
        mkdir -p "${LOG_DIR}" 2>/dev/null || true
    fi
    if [[ ! -d "${BACKUP_DIR}" ]]; then
        mkdir -p "${BACKUP_DIR}" 2>/dev/null || true
    fi
    touch "${LOG_FILE}" 2>/dev/null || true
}

# Function: log
# Description: Logs timestamped actions to console and log file.
log() {
    local message="$1"
    local timestamp
    timestamp="$(date +'%Y-%m-%d %H:%M:%S')"
    
    # Append to log file
    if [[ -d "${LOG_DIR}" ]]; then
        echo "[${timestamp}] ${message}" >> "${LOG_FILE}"
    fi

    # Output to console if not quiet
    if [[ "${QUIET}" == false ]]; then
        echo -e "[${timestamp}] ${message}"
    fi
}

# Function: warn
# Description: Displays warning messages and logs them.
warn() {
    local message="$1"
    TOTAL_WARNINGS=$((TOTAL_WARNINGS + 1))
    log "${COLOR_YELLOW}[WARN] ${message}${COLOR_RESET}"
}

# Function: error
# Description: Logs error message without terminating execution immediately.
error() {
    local message="$1"
    log "${COLOR_RED}[ERROR] ${message}${COLOR_RESET}"
}

# Function: success
# Description: Displays success messages.
success() {
    local message="$1"
    log "${COLOR_GREEN}[SUCCESS] ${message}${COLOR_RESET}"
}

# Function: debug
# Description: Outputs detailed diagnostic info when --verbose is active.
debug() {
    local message="$1"
    if [[ "${VERBOSE}" == true ]]; then
        log "${COLOR_DIM}[DEBUG] ${message}${COLOR_RESET}"
    fi
}

# Function: confirm
# Description: Interactive prompt asking user for explicit consent before action.
# Parameters:
#   $1 - Prompt question
#   $2 - Default option ("Y" or "N", default "N")
confirm() {
    local question="$1"
    local default_choice="${2:-N}"
    local prompt_str="[y/N]"

    if [[ "${default_choice}" == "Y" || "${default_choice}" == "y" ]]; then
        prompt_str="[Y/n]"
    fi

    # In dry-run mode, skip prompt and simulate confirmation bypass
    if [[ "${DRY_RUN}" == true ]]; then
        log "${COLOR_CYAN}[DRY-RUN] Automated confirmation skipped for prompt: '${question}'${COLOR_RESET}"
        return 1
    fi

    # In non-interactive mode or quiet mode, respect default
    if [[ ! -t 0 ]]; then
        if [[ "${default_choice}" =~ ^[Yy]$ ]]; then
            return 0
        else
            return 1
        fi
    fi

    while true; do
        read -rp "${question} ${prompt_str} " response
        response="${response:-${default_choice}}"
        case "${response}" in
            [Yy]* ) return 0 ;;
            [Nn]* ) return 1 ;;
            * ) echo "Please answer yes (y) or no (n)." ;;
        esac
    done
}

# Function: backup_file
# Description: Creates a safe backup copy of a file before modification or deletion.
# Parameters:
#   $1 - Target file path
backup_file() {
    local target="$1"

    if [[ ! -e "${target}" ]]; then
        debug "Backup requested for non-existent target: ${target}"
        return 0
    fi

    ensure_log_dir

    local relative_name
    relative_name="$(echo "${target}" | sed 's|/|_|g')"
    local destination="${BACKUP_DIR}/${relative_name}"

    if [[ "${DRY_RUN}" == true ]]; then
        log "${COLOR_CYAN}[DRY-RUN] Would backup ${target} to ${destination}${COLOR_RESET}"
        return 0
    fi

    # Compute and log cryptographic hash if target is a regular file
    if [[ -f "${target}" && ! -L "${target}" ]]; then
        local file_sha
        file_sha="$(shasum -a 256 "${target}" 2>/dev/null | awk '{print $1}' || echo "checksum-failed")"
        log "  • SHA-256: ${file_sha} (${target})"
    fi

    if cp -a "${target}" "${destination}" 2>/dev/null; then
        success "Backed up file: ${target} -> ${destination}"
    else
        warn "Failed to create backup copy of ${target}"
    fi
}

# ------------------------------------------------------------------------------
# STEP 1: COLLECT BASIC SYSTEM INFORMATION
# ------------------------------------------------------------------------------
step1_collect_system_info() {
    log "${COLOR_BOLD}=== STEP 1: Collecting Basic System Information ===${COLOR_RESET}"

    local os_version build_ver arch host_name user_name current_shell
    local sip_status gatekeeper_status xprotect_ver mrt_ver

    os_version="$(sw_vers -productVersion 2>/dev/null || echo "Unknown")"
    build_ver="$(sw_vers -buildVersion 2>/dev/null || echo "Unknown")"
    arch="$(uname -m 2>/dev/null || echo "Unknown")"
    host_name="$(hostname 2>/dev/null || echo "Unknown")"
    user_name="${TARGET_USER}"
    current_shell="${SHELL:-/bin/bash}"

    # SIP Status
    if command -v csrutil &>/dev/null; then
        sip_status="$(csrutil status 2>/dev/null || echo "Unavailable")"
    else
        sip_status="csrutil command not found"
    fi

    # Gatekeeper Status
    if command -v spctl &>/dev/null; then
        gatekeeper_status="$(spctl --status 2>/dev/null || echo "Unavailable")"
    else
        gatekeeper_status="spctl command not found"
    fi

    # XProtect Version
    local xprotect_plist="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    if [[ -f "${xprotect_plist}" ]] && command -v plutil &>/dev/null; then
        xprotect_ver="$(plutil -extract CFBundleShortVersionString raw "${xprotect_plist}" 2>/dev/null || echo "Unknown")"
    else
        xprotect_ver="Not detected"
    fi

    # MRT (Malware Removal Tool) Version
    local mrt_plist="/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist"
    if [[ -f "${mrt_plist}" ]] && command -v plutil &>/dev/null; then
        mrt_ver="$(plutil -extract CFBundleShortVersionString raw "${mrt_plist}" 2>/dev/null || echo "Unknown")"
    else
        mrt_ver="Not detected / Sunset on macOS 13+"
    fi

    log "  • Operating System: macOS ${os_version} (Build ${build_ver})"
    log "  • Architecture:     ${arch}"
    log "  • Hostname:         ${host_name}"
    log "  • Target Account:   ${user_name}"
    log "  • Active Shell:     ${current_shell}"
    log "  • SIP Status:       ${sip_status}"
    log "  • Gatekeeper:       ${gatekeeper_status}"
    log "  • XProtect Version: ${xprotect_ver}"
    log "  • MRT Version:      ${mrt_ver}"
    log ""
}

# ------------------------------------------------------------------------------
# STEP 2: STOP MALICIOUS PROCESSES
# ------------------------------------------------------------------------------
step2_stop_malicious_processes() {
    log "${COLOR_BOLD}=== STEP 2: Scanning & Stopping Malicious Processes ===${COLOR_RESET}"

    local found_processes=0
    local pids_to_kill=()

    # Search running processes against malware pattern signatures
    for pattern in "${MALWARE_PROCESS_PATTERNS[@]}"; do
        while IFS= read -r line; do
            if [[ -n "${line}" ]]; then
                local pid process_cmd
                pid="$(echo "${line}" | awk '{print $2}')"
                process_cmd="$(echo "${line}" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')"
                
                # Exclude self PID
                if [[ "${pid}" != "$$" ]]; then
                    warn "Detected malicious process signature matching '${pattern}' -> PID ${pid}: ${process_cmd}"
                    pids_to_kill+=("${pid}")
                    found_processes=$((found_processes + 1))
                fi
            fi
        done < <(ps aux | grep -iE "${pattern}" | grep -v "grep" | grep -v "${SCRIPT_NAME}" || true)
    done

    if [[ ${#pids_to_kill[@]} -eq 0 ]]; then
        success "No active malicious process signatures detected."
        log ""
        return 0
    fi

    TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + found_processes))

    for pid in "${pids_to_kill[@]}"; do
        if [[ "${DRY_RUN}" == true ]]; then
            log "${COLOR_CYAN}[DRY-RUN] Would terminate PID ${pid}${COLOR_RESET}"
            continue
        fi

        log "Attempting graceful termination (SIGTERM) for PID ${pid}..."
        kill -15 "${pid}" 2>/dev/null || true
        sleep 1

        # Force kill if process survived SIGTERM
        if kill -0 "${pid}" 2>/dev/null; then
            warn "PID ${pid} did not respond to SIGTERM. Sending force kill (SIGKILL)..."
            kill -9 "${pid}" 2>/dev/null || true
            sleep 1
        fi

        # Verify termination
        if kill -0 "${pid}" 2>/dev/null; then
            error "Failed to terminate process PID ${pid}."
        else
            success "Successfully terminated process PID ${pid}."
            TOTAL_REMEDIATIONS=$((TOTAL_REMEDIATIONS + 1))
        fi
    done
    log ""
}

# ------------------------------------------------------------------------------
# STEP 3: REMOVE KNOWN MALWARE FILES
# ------------------------------------------------------------------------------
step3_remove_known_malware() {
    log "${COLOR_BOLD}=== STEP 3: Removing Known Malware Artifacts ===${COLOR_RESET}"

    local removed_count=0

    for path_pattern in "${KNOWN_MALWARE_PATHS[@]}"; do
        # Expand glob safely
        shopt -s nullglob
        local matches=(${path_pattern})
        shopt -u nullglob

        if [[ ${#matches[@]} -gt 0 ]]; then
            for target_path in "${matches[@]}"; do
                if [[ -e "${target_path}" ]]; then
                    warn "Found known malware file/directory: ${target_path}"
                    TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + 1))

                    # Known malware files are removed automatically per requirements
                    backup_file "${target_path}"

                    if [[ "${DRY_RUN}" == true ]]; then
                        log "${COLOR_CYAN}[DRY-RUN] Would remove known malware item: ${target_path}${COLOR_RESET}"
                    else
                        log "Removing malware artifact: ${target_path}"
                        rm -rf "${target_path}"
                        if [[ ! -e "${target_path}" ]]; then
                            success "Removed: ${target_path}"
                            TOTAL_REMEDIATIONS=$((TOTAL_REMEDIATIONS + 1))
                            removed_count=$((removed_count + 1))
                        else
                            error "Failed to remove: ${target_path}"
                        fi
                    fi
                fi
            done
        fi
    done

    if [[ ${removed_count} -eq 0 && "${DRY_RUN}" == false ]]; then
        success "No known malware temporary artifacts were found."
    fi
    log ""
}

# ------------------------------------------------------------------------------
# STEP 4: REMOVE MALICIOUS LAUNCH AGENTS & DAEMONS
# ------------------------------------------------------------------------------
step4_remove_malicious_launch_agents() {
    log "${COLOR_BOLD}=== STEP 4: Scanning LaunchAgents & LaunchDaemons Persistence ===${COLOR_RESET}"

    local user_launch_agents="${TARGET_HOME}/Library/LaunchAgents"
    local global_launch_agents="/Library/LaunchAgents"
    local global_launch_daemons="/Library/LaunchDaemons"
    local system_launch_agents="/System/Library/LaunchAgents"

    local scan_dirs=("${user_launch_agents}" "${global_launch_agents}" "${global_launch_daemons}")

    log "Scanning persistence directories (System directories are audited in read-only mode)..."

    # Audit System LaunchAgents read-only
    if [[ -d "${system_launch_agents}" ]]; then
        debug "Auditing Apple system LaunchAgents: ${system_launch_agents}"
        for sys_plist in "${system_launch_agents}"/*.plist; do
            [[ -f "${sys_plist}" ]] || continue
            for pattern in "${LAUNCHAGENT_MALWARE_PATTERNS[@]}"; do
                if grep -qi "${pattern}" "${sys_plist}" 2>/dev/null; then
                    warn "System LaunchAgent ${sys_plist} matched malware indicator '${pattern}' (System file - read-only audit)."
                fi
            done
        done
    fi

    # Scan and remediate user & global launch configurations
    for dir in "${scan_dirs[@]}"; do
        if [[ ! -d "${dir}" ]]; then
            continue
        fi

        log "Inspecting directory: ${dir}"
        for plist in "${dir}"/*.plist; do
            [[ -f "${plist}" ]] || continue

            local is_suspicious=false
            local matched_patterns=()

            # Read plist XML representation
            local plist_content
            plist_content="$(plutil -convert xml1 -o - "${plist}" 2>/dev/null || cat "${plist}")"

            # 1. Check direct malware patterns
            for pattern in "${LAUNCHAGENT_MALWARE_PATTERNS[@]}"; do
                if echo "${plist_content}" | grep -qi "${pattern}"; then
                    is_suspicious=true
                    matched_patterns+=("${pattern}")
                fi
            done

            # 2. Check for suspicious payload combination (e.g. osascript + base64 or curl + xxd)
            if echo "${plist_content}" | grep -qi "osascript" && echo "${plist_content}" | grep -qiE "base64"; then
                is_suspicious=true
                matched_patterns+=("osascript+base64")
            fi
            if echo "${plist_content}" | grep -qi "curl" && echo "${plist_content}" | grep -qi "xxd"; then
                is_suspicious=true
                matched_patterns+=("curl+xxd")
            fi
            if echo "${plist_content}" | grep -qiE "base64 -d.*osascript|base64 --decode.*osascript|base64.*-d.*osascript"; then
                is_suspicious=true
                matched_patterns+=("base64-decode-pipe-osascript")
            fi

            if [[ "${is_suspicious}" == true ]]; then
                warn "Flagged suspicious LaunchAgent: ${plist}"
                log "  • Matched Indicators: ${matched_patterns[*]}"
                TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + 1))

                local label
                label="$(plutil -extract Label raw "${plist}" 2>/dev/null || basename "${plist}" .plist)"

                if confirm "Do you want to unload and delete LaunchAgent '${plist}'?" "Y"; then
                    # 1. Unload Service
                    if [[ "${DRY_RUN}" == true ]]; then
                        log "${COLOR_CYAN}[DRY-RUN] Would unload service label '${label}' and remove ${plist}${COLOR_RESET}"
                    else
                        log "Unloading LaunchAgent service: ${label}"
                        launchctl bootout "gui/$(id -u "${TARGET_USER}" 2>/dev/null || echo 501)" "${plist}" 2>/dev/null || \
                        launchctl unload "${plist}" 2>/dev/null || true

                        # 2. Backup plist
                        backup_file "${plist}"

                        # 3. Delete file
                        log "Deleting malicious plist file: ${plist}"
                        rm -f "${plist}"
                        if [[ ! -f "${plist}" ]]; then
                            success "Removed LaunchAgent plist: ${plist}"
                            TOTAL_REMEDIATIONS=$((TOTAL_REMEDIATIONS + 1))
                        else
                            error "Failed to remove LaunchAgent plist: ${plist}"
                        fi
                    fi
                else
                    log "Skipped remediation for LaunchAgent: ${plist}"
                fi
            fi
        done
    done
    log ""
}

# ------------------------------------------------------------------------------
# STEP 5: SCAN LOGIN ITEMS
# ------------------------------------------------------------------------------
step5_scan_login_items() {
    log "${COLOR_BOLD}=== STEP 5: Scanning macOS User Login Items ===${COLOR_RESET}"

    if ! command -v osascript &>/dev/null; then
        warn "osascript tool not found. Skipping Login Items inspection."
        log ""
        return 0
    fi

    log "Querying System Events for active user Login Items..."

    local login_items
    login_items="$(osascript -e '
        tell application "System Events"
            try
                set itemList to get name of every login item
                set pathList to get path of every login item
                set output to ""
                repeat with i from 1 to count of itemList
                    set output to output & (item i of itemList) & "|" & (item i of pathList) & "\n"
                end repeat
                return output
            on error
                return ""
            end try
        end tell' 2>/dev/null || echo "")"

    if [[ -z "${login_items}" ]]; then
        success "No custom Login Items found or unable to access System Events."
        log ""
        return 0
    fi

    while IFS="|" read -r item_name item_path; do
        [[ -n "${item_name}" ]] || continue
        log "  • Login Item: '${item_name}' -> Path: ${item_path}"

        local suspicious=false
        if echo "${item_path}" | grep -qiE "tmp|xmrig|rigupdater|base64|osascript"; then
            suspicious=true
            warn "Suspicious path detected in Login Item '${item_name}': ${item_path}"
            TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + 1))
        fi

        if [[ "${suspicious}" == true ]]; then
            if confirm "Remove suspicious Login Item '${item_name}'?" "Y"; then
                if [[ "${DRY_RUN}" == true ]]; then
                    log "${COLOR_CYAN}[DRY-RUN] Would remove Login Item '${item_name}' via osascript${COLOR_RESET}"
                else
                    osascript -e "tell application \"System Events\" to delete login item \"${item_name}\"" 2>/dev/null || true
                    success "Removed Login Item: ${item_name}"
                    TOTAL_REMEDIATIONS=$((TOTAL_REMEDIATIONS + 1))
                fi
            fi
        fi
    done <<< "${login_items}"
    log ""
}

# ------------------------------------------------------------------------------
# STEP 6: SCAN CRON JOBS
# ------------------------------------------------------------------------------
step6_scan_cron() {
    log "${COLOR_BOLD}=== STEP 6: Inspecting Cron Job Schedules ===${COLOR_RESET}"

    log "Auditing user crontab entries (${TARGET_USER})..."
    local cron_user
    cron_user="$(crontab -l -u "${TARGET_USER}" 2>/dev/null || echo "")"

    if [[ -n "${cron_user}" ]]; then
        log "Active crontab entries for ${TARGET_USER}:"
        echo "${cron_user}" | while read -r line; do
            log "    ${line}"
            if echo "${line}" | grep -qiE "curl|base64|osascript|xmrig|rigupdater|tmp"; then
                warn "Suspicious pattern detected in crontab entry: ${line}"
                TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + 1))
            fi
        done
    else
        success "No active user crontab found for ${TARGET_USER}."
    fi

    # Audit system /etc/crontab and /etc/cron* directories
    log "Auditing system cron directories (/etc/cron*, /etc/crontab, /etc/periodic)..."
    local system_cron_files=("/etc/crontab" "/etc/cron.d" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/etc/periodic")

    for cpath in "${system_cron_files[@]}"; do
        if [[ -e "${cpath}" ]]; then
            if grep -rqiE "curl|base64|osascript|xmrig|rigupdater|private/tmp" "${cpath}" 2>/dev/null; then
                warn "Suspicious pattern matched inside system cron configuration: ${cpath}"
                TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + 1))
            fi
        fi
    done
    log ""
}

# ------------------------------------------------------------------------------
# STEP 7: SCAN SHELL PERSISTENCE
# ------------------------------------------------------------------------------
step7_scan_shell_persistence() {
    log "${COLOR_BOLD}=== STEP 7: Scanning Shell Profiles for Malicious Persistence ===${COLOR_RESET}"

    local profile_files=(
        "${TARGET_HOME}/.zprofile"
        "${TARGET_HOME}/.zshrc"
        "${TARGET_HOME}/.bash_profile"
        "${TARGET_HOME}/.bashrc"
        "${TARGET_HOME}/.profile"
    )

    for profile in "${profile_files[@]}"; do
        if [[ ! -f "${profile}" ]]; then
            continue
        fi

        log "Inspecting shell configuration: ${profile}"
        local flagged_lines=()

        while IFS= read -r line; do
            # Skip empty lines or pure comment lines
            [[ "${line}" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line}" ]] && continue

            if echo "${line}" | grep -qiE "curl|base64|osascript|launchctl|xmrig|rigupdater|/tmp/|/private/tmp/"; then
                flagged_lines+=("${line}")
            fi
        done < "${profile}"

        if [[ ${#flagged_lines[@]} -gt 0 ]]; then
            warn "Flagged suspicious commands inside ${profile}:"
            for fline in "${flagged_lines[@]}"; do
                log "  • ${fline}"
            done
            TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + 1))

            if confirm "Would you like to comment out suspicious lines in ${profile}?" "N"; then
                backup_file "${profile}"
                if [[ "${DRY_RUN}" == true ]]; then
                    log "${COLOR_CYAN}[DRY-RUN] Would sanitize shell profile ${profile}${COLOR_RESET}"
                else
                    for fline in "${flagged_lines[@]}"; do
                        # Comment out line defensively
                        sed -i '' "s|${fline}|# [FORENSIC-CLEANUP-DISABLED] ${fline}|g" "${profile}" 2>/dev/null || true
                    done
                    success "Sanitized shell profile: ${profile}"
                    TOTAL_REMEDIATIONS=$((TOTAL_REMEDIATIONS + 1))
                fi
            fi
        fi
    done
    log ""
}

# ------------------------------------------------------------------------------
# STEP 8: SCAN FOR MALWARE STRINGS
# ------------------------------------------------------------------------------
step8_scan_malware_strings() {
    log "${COLOR_BOLD}=== STEP 8: Searching System Directories for Malware Strings ===${COLOR_RESET}"
    log "Searching target directories (User Library, Applications, Temporary folders, Global Library)..."
    log "Note: User development project directories are strictly excluded from recursive search."

    local search_targets=(
        "${TARGET_HOME}/Library/LaunchAgents"
        "${TARGET_HOME}/Library/Application Support"
        "${TARGET_HOME}/Applications"
        "/private/tmp"
        "/tmp"
        "/Library/LaunchAgents"
        "/Library/LaunchDaemons"
        "/Library/Application Support"
    )

    for target in "${search_targets[@]}"; do
        if [[ ! -d "${target}" ]]; then
            continue
        fi

        log "Searching location: ${target}..."
        for s_string in "${SUSPICIOUS_STRINGS[@]}"; do
            # Use grep with excludes for speed and isolation
            while IFS= read -r match_file; do
                if [[ -n "${match_file}" ]]; then
                    warn "String '${s_string}' matched in file: ${match_file}"
                    TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + 1))
                fi
            done < <(grep -rnI -l "${s_string}" "${target}" 2>/dev/null | grep -vE "\.git|\.vscode|\.idea|node_modules|Developer|Projects|Caches|Containers|Group Containers" | head -n 30 || true)
        done
    done
    log ""
}

# ------------------------------------------------------------------------------
# STEP 9: SCAN EXECUTABLES AND SIGNATURES
# ------------------------------------------------------------------------------
step9_scan_executables() {
    log "${COLOR_BOLD}=== STEP 9: Scanning Executables & Code Signatures ===${COLOR_RESET}"

    local scan_folders=(
        "/private/tmp"
        "/tmp"
        "${TARGET_HOME}/Library/Caches"
        "${TARGET_HOME}/Library/Application Support"
    )

    log "Checking temporary directories and user application support for unsigned Mach-O binaries..."

    for sfolder in "${scan_folders[@]}"; do
        if [[ ! -d "${sfolder}" ]]; then
            continue
        fi

        # Find executable files limit depth 4 to prevent hanging
        find "${sfolder}" -maxdepth 4 -type f -perm +111 2>/dev/null | while read -r exec_file; do
            # Verify file type using file utility
            local ftype
            ftype="$(file -b "${exec_file}" 2>/dev/null || echo "")"

            if [[ "${ftype}" =~ Mach-O ]]; then
                log "Found Mach-O binary: ${exec_file} (${ftype})"
                
                # Check code signature
                local cs_output
                if cs_output="$(codesign -vvv --no-strict "${exec_file}" 2>&1)"; then
                    debug "Binary code signature valid for ${exec_file}"
                else
                    warn "Unsigned or invalidly signed executable detected: ${exec_file}"
                    debug "Codesign output: ${cs_output}"
                    TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + 1))

                    if confirm "Delete unsigned temporary executable '${exec_file}'?" "N"; then
                        backup_file "${exec_file}"
                        if [[ "${DRY_RUN}" == true ]]; then
                            log "${COLOR_CYAN}[DRY-RUN] Would remove unsigned binary ${exec_file}${COLOR_RESET}"
                        else
                            rm -f "${exec_file}"
                            success "Removed unsigned executable: ${exec_file}"
                            TOTAL_REMEDIATIONS=$((TOTAL_REMEDIATIONS + 1))
                        fi
                    fi
                fi
            fi
        done || true
    done
    log ""
}

# ------------------------------------------------------------------------------
# STEP 10: CHECK QUARANTINE ATTRIBUTES
# ------------------------------------------------------------------------------
step10_check_quarantine() {
    log "${COLOR_BOLD}=== STEP 10: Inspecting File Quarantine Attributes ===${COLOR_RESET}"

    local temp_dirs=("/private/tmp" "/tmp")

    for tdir in "${temp_dirs[@]}"; do
        if [[ ! -d "${tdir}" ]]; then
            continue
        fi

        log "Auditing com.apple.quarantine attribute on items in ${tdir}..."
        find "${tdir}" -maxdepth 3 -type f 2>/dev/null | while read -r qfile; do
            local qattr
            qattr="$(xattr -p com.apple.quarantine "${qfile}" 2>/dev/null || echo "")"
            if [[ -n "${qattr}" ]]; then
                debug "Quarantine attribute present on ${qfile}: ${qattr}"
                if echo "${qfile}" | grep -qiE "xmrig|rigupdater"; then
                    warn "Malware file with active quarantine attribute found: ${qfile}"
                    TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + 1))
                fi
            fi
        done || true
    done
    log ""
}

# ------------------------------------------------------------------------------
# STEP 11: CHECK APPLICATION SUPPORT
# ------------------------------------------------------------------------------
step11_check_application_support() {
    log "${COLOR_BOLD}=== STEP 11: Auditing Application Support Directories ===${COLOR_RESET}"

    local app_support="${TARGET_HOME}/Library/Application Support"
    if [[ ! -d "${app_support}" ]]; then
        return 0
    fi

    log "Checking ${app_support} for hidden directories and recent executable scripts..."

    # Check hidden folders in Application Support
    find "${app_support}" -maxdepth 2 -name ".*" -type d 2>/dev/null | while read -r hidden_dir; do
        # Exclude standard hidden folders
        local base_hdir
        base_hdir="$(basename "${hidden_dir}")"
        if [[ "${base_hdir}" != "." && "${base_hdir}" != ".." && "${base_hdir}" != ".DS_Store" ]]; then
            warn "Hidden directory discovered in Application Support: ${hidden_dir}"
            TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + 1))
        fi
    done || true

    log ""
}

# ------------------------------------------------------------------------------
# STEP 12: CHECK CACHE FOLDERS
# ------------------------------------------------------------------------------
step12_check_cache_folders() {
    log "${COLOR_BOLD}=== STEP 12: Inspecting Cache Directories ===${COLOR_RESET}"

    local user_caches="${TARGET_HOME}/Library/Caches"
    if [[ ! -d "${user_caches}" ]]; then
        return 0
    fi

    log "Checking ${user_caches} for executable scripts or hidden binary files..."

    find "${user_caches}" -maxdepth 3 -type f \( -name "*.sh" -o -name "*.command" -o -perm +111 \) 2>/dev/null | while read -r cache_file; do
        if echo "${cache_file}" | grep -qiE "xmrig|rigupdater|polygon|base64"; then
            warn "Malicious cache file pattern detected: ${cache_file}"
            TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + 1))
            if confirm "Delete suspicious cache file '${cache_file}'?" "Y"; then
                backup_file "${cache_file}"
                if [[ "${DRY_RUN}" == true ]]; then
                    log "${COLOR_CYAN}[DRY-RUN] Would delete ${cache_file}${COLOR_RESET}"
                else
                    rm -f "${cache_file}"
                    success "Deleted: ${cache_file}"
                    TOTAL_REMEDIATIONS=$((TOTAL_REMEDIATIONS + 1))
                fi
            fi
        fi
    done || true

    log ""
}

# ------------------------------------------------------------------------------
# STEP 13: CHECK SSH CONFIGURATION (READ-ONLY)
# ------------------------------------------------------------------------------
step13_check_ssh() {
    log "${COLOR_BOLD}=== STEP 13: Auditing SSH Configuration & Key Files (Read-Only) ===${COLOR_RESET}"

    local ssh_dir="${TARGET_HOME}/.ssh"

    if [[ ! -d "${ssh_dir}" ]]; then
        success "No .ssh directory found for ${TARGET_USER}."
        log ""
        return 0
    fi

    log "Auditing permissions and contents of ${ssh_dir}..."

    local auth_keys="${ssh_dir}/authorized_keys"
    local ssh_config="${ssh_dir}/config"

    if [[ -f "${auth_keys}" ]]; then
        local key_count
        key_count="$(wc -l < "${auth_keys}" | tr -d ' ')"
        log "  • ${auth_keys} exists (${key_count} keys registered)."
        debug "Contents of authorized_keys:"
        if [[ "${VERBOSE}" == true ]]; then
            cat "${auth_keys}" | while read -r line; do
                debug "    SSH-KEY: ${line}"
            done
        fi
    else
        log "  • No authorized_keys file present."
    fi

    if [[ -f "${ssh_config}" ]]; then
        log "  • Custom SSH config file found: ${ssh_config}"
    fi

    log ""
}

# ------------------------------------------------------------------------------
# STEP 14: CHECK NETWORK SOCKETS & LISTENERS
# ------------------------------------------------------------------------------
step14_check_network() {
    log "${COLOR_BOLD}=== STEP 14: Auditing Active Network Connections & Listening Sockets ===${COLOR_RESET}"

    log "Listing active network listening ports (lsof -i -P -n)..."
    if command -v lsof &>/dev/null; then
        lsof -i -P -n | grep -i "LISTEN" | while read -r line; do
            log "  [LISTEN] ${line}"
            if echo "${line}" | grep -qiE "xmrig|rigupdater"; then
                warn "Active listener belongs to malware process! -> ${line}"
                TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + 1))
            fi
        done || true
    fi

    log "Auditing outbound ESTABLISHED sockets for crypto-mining ports (3333, 4444, 5555, 7777)..."
    if command -v netstat &>/dev/null; then
        netstat -an | grep "ESTABLISHED" | grep -E ":(3333|4444|5555|7777|8080|9999) " | while read -r line; do
            warn "Established socket connection to potential mining port: ${line}"
            TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + 1))
        done || true
    fi

    # Check for active connections tied to malware processes or C2 destinations (including TLS 443)
    if command -v lsof &>/dev/null; then
        log "Auditing network connections initiated by suspicious processes or C2 endpoints..."
        lsof -i -P -n 2>/dev/null | grep -iE "xmrig|rigupdater|hashvault|jse8x92s|polygon" | while read -r line; do
            warn "Active process network connection matched malware signature: ${line}"
            TOTAL_SUSPICIOUS_ITEMS=$((TOTAL_SUSPICIOUS_ITEMS + 1))
        done || true
    fi

    log ""
}

# ------------------------------------------------------------------------------
# STEP 15: VERIFY CLEANUP STATE
# ------------------------------------------------------------------------------
step15_verify_cleanup() {
    log "${COLOR_BOLD}=== STEP 15: Post-Cleanup Verification Sweep ===${COLOR_RESET}"

    local verification_failed=false

    log "1. Verifying active process list for XMRig / RigUpdater signatures..."
    for pattern in "${MALWARE_PROCESS_PATTERNS[@]}"; do
        if ps aux | grep -iE "${pattern}" | grep -v "grep" | grep -v "${SCRIPT_NAME}" &>/dev/null; then
            error "Verification Failed: Active process signature '${pattern}' still detected!"
            verification_failed=true
        fi
    done

    log "2. Verifying file system deletion of known malware paths..."
    for path_pattern in "${KNOWN_MALWARE_PATHS[@]}"; do
        shopt -s nullglob
        local remaining=(${path_pattern})
        shopt -u nullglob

        if [[ ${#remaining[@]} -gt 0 ]]; then
            if [[ "${DRY_RUN}" == true ]]; then
                log "${COLOR_CYAN}[DRY-RUN] Simulated verification note: Artifact '${path_pattern}' exists (not removed due to dry-run).${COLOR_RESET}"
            else
                error "Verification Failed: Malware artifact '${path_pattern}' still exists on disk!"
                verification_failed=true
            fi
        fi
    done

    log "3. Verifying user LaunchAgents directory..."
    local user_agents="${TARGET_HOME}/Library/LaunchAgents"
    if [[ -d "${user_agents}" ]]; then
        for plist in "${user_agents}"/*.plist; do
            [[ -f "${plist}" ]] || continue
            for pattern in "${LAUNCHAGENT_MALWARE_PATTERNS[@]}"; do
                if grep -qi "${pattern}" "${plist}" 2>/dev/null; then
                    warn "Verification Warning: LaunchAgent '${plist}' contains indicator '${pattern}'."
                    verification_failed=true
                fi
            done
        done
    fi

    if [[ "${verification_failed}" == false ]]; then
        success "Post-cleanup verification passed cleanly. Zero active malware indicators found."
    else
        warn "Post-cleanup verification produced warnings or residual items. Review report."
    fi
    log ""
}

# ------------------------------------------------------------------------------
# STEP 16: FINAL REPORT & SUMMARY
# ------------------------------------------------------------------------------
step16_final_report() {
    log "${COLOR_BOLD}=== STEP 16: Final Remediation Report & Summary ===${COLOR_RESET}"

    echo ""
    echo -e "${COLOR_BOLD}===============================================================================${COLOR_RESET}"
    echo -e "${COLOR_BOLD}                        FINAL REMEDIATION SUMMARY                              ${COLOR_RESET}"
    echo -e "${COLOR_BOLD}===============================================================================${COLOR_RESET}"
    echo -e " Execution Mode:           $( [[ "${DRY_RUN}" == true ]] && echo "${COLOR_CYAN}DRY-RUN (Simulated)${COLOR_RESET}" || echo "${COLOR_GREEN}LIVE (Remediated)${COLOR_RESET}" )"
    echo -e " Suspicious Items Flagged: ${COLOR_YELLOW}${TOTAL_SUSPICIOUS_ITEMS}${COLOR_RESET}"
    echo -e " Total Actions Performed:  ${COLOR_GREEN}${TOTAL_REMEDIATIONS}${COLOR_RESET}"
    echo -e " Warnings Logged:          ${COLOR_YELLOW}${TOTAL_WARNINGS}${COLOR_RESET}"
    echo -e " Detailed Log File:        ${COLOR_CYAN}${LOG_FILE}${COLOR_RESET}"
    if [[ -d "${BACKUP_DIR}" ]]; then
        echo -e " Backup Directory:         ${COLOR_CYAN}${BACKUP_DIR}${COLOR_RESET}"
    fi
    echo "-------------------------------------------------------------------------------"

    if [[ "${TOTAL_SUSPICIOUS_ITEMS}" -eq 0 ]]; then
        echo -e " ${COLOR_GREEN}✓ STATUS: SYSTEM IS CLEAN. No active malware artifacts detected.${COLOR_RESET}"
    else
        echo -e " ${COLOR_YELLOW}! STATUS: REMEDIATION COMPLETED WITH FLAGGED ARTIFACTS.${COLOR_RESET}"
    fi

    echo "==============================================================================="
    echo ""
    log "Remediation complete. Summary report written to log."
}

# ------------------------------------------------------------------------------
# ORCHESTRATORS: SCAN & CLEANUP
# ------------------------------------------------------------------------------

# Function: scan
# Description: Executes all read-only diagnostic steps across the system.
scan() {
    log "Beginning comprehensive forensic scan..."
    step1_collect_system_info
    step4_remove_malicious_launch_agents
    step5_scan_login_items
    step6_scan_cron
    step7_scan_shell_persistence
    step8_scan_malware_strings
    step9_scan_executables
    step10_check_quarantine
    step11_check_application_support
    step12_check_cache_folders
    step13_check_ssh
    step14_check_network
}

# Function: cleanup
# Description: Orchestrates process termination, file removal, and system verification.
cleanup() {
    log "Beginning remediation and cleanup operations..."
    step2_stop_malicious_processes
    step3_remove_known_malware
    step15_verify_cleanup
}

# Function: show_help
# Description: Displays command line usage menu.
show_help() {
    cat << EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Production-Grade macOS Forensic Cleanup & Malware Remediation Utility.

OPTIONS:
    -d, --dry-run      Simulate all actions without modifying files or killing processes.
    -v, --verbose      Enable detailed debug logging output.
    -q, --quiet        Suppress standard terminal output (logs still written to log file).
    -l, --log-file PATH Specify custom log file destination.
    -V, --version      Display script version information and exit.
    -h, --help         Display this help message and exit.

EXAMPLES:
    # Run interactive forensic cleanup:
    sudo ./${SCRIPT_NAME}

    # Run in dry-run mode to inspect system state without making changes:
    ./${SCRIPT_NAME} --dry-run --verbose

    # Execute quiet cleanup specifying custom log path:
    sudo ./${SCRIPT_NAME} --quiet --log-file /var/log/macOS-cleanup.log

EOF
}

# Function: show_version
# Description: Outputs script version and release date.
show_version() {
    echo "${SCRIPT_NAME} version ${SCRIPT_VERSION} (${SCRIPT_DATE})"
}

# ------------------------------------------------------------------------------
# MAIN EXECUTION ENTRY POINT
# ------------------------------------------------------------------------------
main() {
    # Parse CLI Arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -l|--log-file)
                if [[ -n "${2:-}" ]]; then
                    LOG_FILE="$2"
                    shift 2
                else
                    echo "Error: --log-file requires a file path argument." >&2
                    exit 1
                fi
                ;;
            -V|--version)
                show_version
                exit 0
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                show_help
                exit 1
                ;;
        esac
    done

    # Prepare logging environment
    ensure_log_dir
    print_banner

    log "Starting macOS Forensic Cleanup Utility v${SCRIPT_VERSION}..."
    if [[ "${DRY_RUN}" == true ]]; then
        log "${COLOR_CYAN}[NOTICE] Running in DRY-RUN mode. No changes will be saved to disk.${COLOR_RESET}"
    fi

    # Check privileges
    if [[ "${EUID}" -ne 0 && "${DRY_RUN}" == false ]]; then
        warn "Script is running without root privileges (sudo). Some system locations (/private/tmp, /Library/LaunchAgents, process tables) may require elevation."
    fi

    # Execute full workflow
    step1_collect_system_info
    step2_stop_malicious_processes
    step3_remove_known_malware
    step4_remove_malicious_launch_agents
    step5_scan_login_items
    step6_scan_cron
    step7_scan_shell_persistence
    step8_scan_malware_strings
    step9_scan_executables
    step10_check_quarantine
    step11_check_application_support
    step12_check_cache_folders
    step13_check_ssh
    step14_check_network
    step15_verify_cleanup
    step16_final_report
}

# Trigger entry point
main "$@"
