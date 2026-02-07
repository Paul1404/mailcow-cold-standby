#!/bin/bash

###############################################################################
# Mailcow Backup to Hetzner Storage Box
# 
# This script automates the backup of mailcow-dockerized to a Hetzner storage
# box using rsync over SSH. It includes disk space checks, lock file protection,
# and integrity verification with SHA-256 checksums.
#
# Author: Paul Dresch
# License: MIT
###############################################################################

set -euo pipefail

# Configuration file path
CONFIG_FILE="/etc/mailcow-backup/.env"
LOCK_FILE="/var/lock/mailcow-backup.lock"

# Detect if running interactively or from systemd
if [[ -t 1 ]]; then
    INTERACTIVE=true
else
    INTERACTIVE=false
fi

# Color codes for output (only used in interactive mode)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

###############################################################################
# Logging Functions
###############################################################################

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Always write to log file with timestamp
    echo "${timestamp} [${level}] ${message}" >> "${LOG_FILE:-/var/log/mailcow-backup.log}"
}

log_info() {
    log "INFO" "$@"
    
    # Output format depends on context
    if [[ "$INTERACTIVE" == true ]]; then
        # Interactive: colored output without timestamp
        echo -e "${GREEN}[INFO]${NC} $*"
    else
        # Systemd/cron: plain output with timestamp for journal
        echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*"
    fi
}

log_warn() {
    log "WARN" "$@"
    
    if [[ "$INTERACTIVE" == true ]]; then
        echo -e "${YELLOW}[WARN]${NC} $*"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] $*"
    fi
}

log_error() {
    log "ERROR" "$@"
    
    if [[ "$INTERACTIVE" == true ]]; then
        echo -e "${RED}[ERROR]${NC} $*" >&2
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $*" >&2
    fi
}

###############################################################################
# Lock File Management
###############################################################################

acquire_lock() {
    log_info "Checking for existing lock file..."
    
    if [[ -f "$LOCK_FILE" ]]; then
        local lock_pid=$(head -n 1 "$LOCK_FILE")
        local lock_time=$(tail -n 1 "$LOCK_FILE")
        local current_time=$(date +%s)
        local lock_age=$(( (current_time - lock_time) / 3600 ))
        
        log_warn "Lock file exists. PID: $lock_pid, Age: ${lock_age}h"
        
        # Check if the process is still running
        if [[ -d "/proc/$lock_pid" ]]; then
            # Check if lock is stale based on timeout
            if [[ $lock_age -gt ${LOCK_TIMEOUT_HOURS:-24} ]]; then
                log_warn "Lock is stale (older than ${LOCK_TIMEOUT_HOURS}h). Overriding..."
                rm -f "$LOCK_FILE"
            else
                log_error "Backup is already running (PID: $lock_pid). Exiting."
                exit 1
            fi
        else
            log_warn "Process $lock_pid no longer exists. Removing stale lock..."
            rm -f "$LOCK_FILE"
        fi
    fi
    
    # Create lock file
    echo "$$" > "$LOCK_FILE"
    echo "$(date +%s)" >> "$LOCK_FILE"
    log_info "Lock acquired (PID: $$)"
}

release_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        rm -f "$LOCK_FILE"
        log_info "Lock released"
    fi
}

# Ensure lock is released on exit
trap release_lock EXIT INT TERM

###############################################################################
# Configuration Validation
###############################################################################

load_config() {
    log_info "Loading configuration from $CONFIG_FILE"
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        log_error "Please run the installation script first."
        exit 1
    fi
    
    # Source the configuration file
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    
    # Validate required variables
    local required_vars=(
        "HETZNER_HOST"
        "HETZNER_PORT"
        "HETZNER_USER"
        "SSH_KEY_PATH"
        "HETZNER_REMOTE_PATH"
        "MAILCOW_PATH"
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required variable $var is not set in $CONFIG_FILE"
            exit 1
        fi
    done
    
    # Set defaults for optional variables
    BACKUP_COMPONENTS="${BACKUP_COMPONENTS:-all}"
    THREADS="${THREADS:-4}"
    REMOTE_RETENTION_DAYS="${REMOTE_RETENTION_DAYS:-30}"
    LOCK_TIMEOUT_HOURS="${LOCK_TIMEOUT_HOURS:-24}"
    LOG_FILE="${LOG_FILE:-/var/log/mailcow-backup.log}"
    TEMP_BACKUP_DIR="${TEMP_BACKUP_DIR:-/tmp/mailcow-backup}"
    
    log_info "Configuration loaded successfully"
}

###############################################################################
# Email Notification
###############################################################################

send_notification() {
    local status="$1"  # "success" or "failure"
    # For success: args are backup_name, size, hostname, location, count, used, total, percent, free
    # For failure: $2 is error message
    
    # Skip if notifications disabled (accept true, yes, 1)
    local notifications_enabled="${EMAIL_NOTIFICATIONS:-false}"
    if [[ "$notifications_enabled" != "true" ]] && [[ "$notifications_enabled" != "yes" ]] && [[ "$notifications_enabled" != "1" ]]; then
        return 0
    fi
    
    if [[ -z "${NOTIFICATION_EMAIL}" ]]; then
        log_warn "Email notifications enabled but NOTIFICATION_EMAIL not set"
        return 1
    fi
    
    local hostname=$(hostname -f 2>/dev/null || hostname)
    local from_addr="${NOTIFICATION_FROM:-mailcow-backup@${hostname}}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local subject
    local html_body
    
    if [[ "$status" == "success" ]]; then
        local backup_name="$2"
        local backup_size="$3"
        local bk_hostname="$4"
        local location="$5"
        local count="$6"
        local used="$7"
        local total="$8"
        local percent="$9"
        local free="${10}"
        
        subject="=?UTF-8?B?$(echo -n "Mailcow Backup OK - $hostname" | base64 -w0)?="
        
        html_body='<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background-color:#f4f4f7;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f7;padding:24px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">

        <!-- Header -->
        <tr>
          <td style="background-color:#22c55e;padding:24px 32px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="color:#ffffff;font-size:22px;font-weight:700;">&#x2713; Backup Successful</td>
                <td align="right" style="color:rgba(255,255,255,0.85);font-size:13px;">'"$timestamp"'</td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Backup Details -->
        <tr>
          <td style="padding:28px 32px 0;">
            <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f0fdf4;border-radius:6px;border:1px solid #bbf7d0;">
              <tr><td style="padding:16px 20px 8px;color:#166534;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Backup Details</td></tr>
              <tr><td style="padding:0 20px 16px;">
                <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;color:#1e293b;">
                  <tr><td style="padding:6px 0;color:#64748b;width:100px;">Name</td><td style="padding:6px 0;font-weight:600;font-family:monospace;">'"$backup_name"'</td></tr>
                  <tr><td style="padding:6px 0;color:#64748b;">Size</td><td style="padding:6px 0;font-weight:600;">'"$backup_size"'</td></tr>
                  <tr><td style="padding:6px 0;color:#64748b;">Host</td><td style="padding:6px 0;">'"$bk_hostname"'</td></tr>
                </table>
              </td></tr>
            </table>
          </td>
        </tr>

        <!-- Storage Stats -->
        <tr>
          <td style="padding:16px 32px 0;">
            <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f8fafc;border-radius:6px;border:1px solid #e2e8f0;">
              <tr><td style="padding:16px 20px 8px;color:#475569;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Remote Storage (Hetzner)</td></tr>
              <tr><td style="padding:0 20px 6px;">
                <!-- Storage bar -->
                <table width="100%" cellpadding="0" cellspacing="0">
                  <tr><td style="background-color:#e2e8f0;border-radius:4px;height:8px;padding:0;">
                    <div style="background-color:#3b82f6;height:8px;border-radius:4px;width:'"$percent"';min-width:2%;max-width:100%;"></div>
                  </td></tr>
                </table>
              </td></tr>
              <tr><td style="padding:0 20px 16px;">
                <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;color:#1e293b;">
                  <tr><td style="padding:6px 0;color:#64748b;width:100px;">Location</td><td style="padding:6px 0;font-family:monospace;">'"$location"'</td></tr>
                  <tr><td style="padding:6px 0;color:#64748b;">Backups</td><td style="padding:6px 0;font-weight:600;">'"$count"'</td></tr>
                  <tr><td style="padding:6px 0;color:#64748b;">Used</td><td style="padding:6px 0;">'"$used"' of '"$total"' ('"$percent"')</td></tr>
                  <tr><td style="padding:6px 0;color:#64748b;">Free</td><td style="padding:6px 0;">'"$free"'</td></tr>
                </table>
              </td></tr>
            </table>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding:24px 32px;border-top:1px solid #e2e8f0;margin-top:16px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="color:#94a3b8;font-size:12px;">Log: '"${LOG_FILE}"'</td>
                <td align="right"><a href="https://github.com/Paul1404/mailcow-cold-standby" style="color:#3b82f6;font-size:12px;text-decoration:none;">Documentation</a></td>
              </tr>
            </table>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>'
    else
        local error_message="$2"
        
        subject="=?UTF-8?B?$(echo -n "✗ Mailcow Backup FAILED - $hostname" | base64 -w0)?="
        
        # Escape HTML characters in error message
        local safe_message=$(echo "$error_message" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g;s/"/\&quot;/g')
        
        html_body='<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background-color:#f4f4f7;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f7;padding:24px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">

        <!-- Header -->
        <tr>
          <td style="background-color:#ef4444;padding:24px 32px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="color:#ffffff;font-size:22px;font-weight:700;">&#x2717; Backup Failed</td>
                <td align="right" style="color:rgba(255,255,255,0.85);font-size:13px;">'"$timestamp"'</td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Error Details -->
        <tr>
          <td style="padding:28px 32px 0;">
            <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#fef2f2;border-radius:6px;border:1px solid #fecaca;">
              <tr><td style="padding:16px 20px 8px;color:#991b1b;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Error Details</td></tr>
              <tr><td style="padding:0 20px 16px;">
                <p style="margin:0;font-size:14px;color:#1e293b;line-height:1.6;">'"$safe_message"'</p>
              </td></tr>
            </table>
          </td>
        </tr>

        <!-- Action Required -->
        <tr>
          <td style="padding:16px 32px 0;">
            <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f8fafc;border-radius:6px;border:1px solid #e2e8f0;">
              <tr><td style="padding:16px 20px;font-size:14px;color:#475569;">
                <strong>Action Required:</strong> Check the log file for detailed error information.<br>
                <code style="background:#e2e8f0;padding:2px 6px;border-radius:3px;font-size:13px;">cat '"${LOG_FILE}"'</code>
              </td></tr>
            </table>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding:24px 32px;border-top:1px solid #e2e8f0;margin-top:16px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="color:#94a3b8;font-size:12px;">Host: '"$hostname"'</td>
                <td align="right"><a href="https://github.com/Paul1404/mailcow-cold-standby" style="color:#3b82f6;font-size:12px;text-decoration:none;">Documentation</a></td>
              </tr>
            </table>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>'
    fi
    
    # Primary method: Use docker exec to send via postfix container (most reliable)
    local postfix_container=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -E 'postfix-mailcow' | head -1)
    
    if [[ -n "$postfix_container" ]]; then
        log_info "Sending email notification via $postfix_container container..."
        
        local email_content="From: ${from_addr}
To: ${NOTIFICATION_EMAIL}
Subject: ${subject}
Date: $(date -R)
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
X-Mailer: mailcow-cold-standby

${html_body}"
        
        if echo "$email_content" | docker exec -i "$postfix_container" sendmail -t -oi 2>/dev/null; then
            log_info "Email notification sent to $NOTIFICATION_EMAIL via postfix container"
            return 0
        else
            log_warn "Failed to send via postfix container, trying fallback methods..."
        fi
    fi
    
    # Fallback: Try localhost SMTP via netcat
    if command -v nc &> /dev/null || command -v netcat &> /dev/null; then
        local nc_cmd=$(command -v nc || command -v netcat)
        
        log_info "Sending email notification via localhost:25..."
        
        {
            echo "EHLO ${hostname}"
            sleep 0.3
            echo "MAIL FROM:<${from_addr}>"
            sleep 0.3
            echo "RCPT TO:<${NOTIFICATION_EMAIL}>"
            sleep 0.3
            echo "DATA"
            sleep 0.3
            echo "From: ${from_addr}"
            echo "To: ${NOTIFICATION_EMAIL}"
            echo "Subject: ${subject}"
            echo "Date: $(date -R)"
            echo "MIME-Version: 1.0"
            echo "Content-Type: text/html; charset=UTF-8"
            echo ""
            echo "${html_body}"
            echo "."
            sleep 0.3
            echo "QUIT"
        } | $nc_cmd localhost 25 > /dev/null 2>&1 && \
            log_info "Email notification sent to $NOTIFICATION_EMAIL" && return 0
    fi
    
    log_warn "Could not send email notification"
    log_warn "Ensure postfix-mailcow container is running or install netcat"
    return 1
}

###############################################################################
# SSH Connection Validation
###############################################################################

test_ssh_connection() {
    log_info "Testing SSH connection to Hetzner storage box..."
    
    if [[ ! -f "$SSH_KEY_PATH" ]]; then
        log_error "SSH key not found: $SSH_KEY_PATH"
        exit 1
    fi
    
    # Check SSH key permissions
    local key_perms=$(stat -c %a "$SSH_KEY_PATH")
    if [[ "$key_perms" != "600" ]] && [[ "$key_perms" != "400" ]]; then
        log_warn "SSH key has insecure permissions: $key_perms (should be 600 or 400)"
    fi
    
    # Test connection
    if ssh -i "$SSH_KEY_PATH" \
           -o BatchMode=yes \
           -o ConnectTimeout=10 \
           -o StrictHostKeyChecking=no \
           -p "$HETZNER_PORT" \
           "${HETZNER_USER}@${HETZNER_HOST}" \
           "exit" 2>/dev/null; then
        log_info "SSH connection successful"
    else
        log_error "SSH connection failed. Check your credentials and network."
        exit 1
    fi
}

###############################################################################
# Disk Space Check
###############################################################################

check_disk_space() {
    log_info "Checking disk space requirements..."
    
    # Calculate mailcow volumes size
    local volumes_size=0
    
    if command -v docker &> /dev/null; then
        # Try to get Docker volumes size - use a simpler, more robust approach
        local docker_root=$(docker info 2>/dev/null | grep "Docker Root Dir" | awk '{print $NF}')
        log_info "Docker root directory: ${docker_root:-not found}"
        
        if [[ -n "$docker_root" ]] && [[ -d "$docker_root/volumes" ]]; then
            # Calculate size of Docker volumes directory
            log_info "Calculating Docker volumes size..."
            volumes_size=$(du -sb "$docker_root/volumes" 2>/dev/null | awk '{print $1}')
            
            if [[ -z "$volumes_size" ]] || [[ "$volumes_size" == "0" ]]; then
                log_warn "Could not determine Docker volumes size, estimating 10GB"
                volumes_size=$((10 * 1024 * 1024 * 1024))
            fi
        else
            log_warn "Docker volumes directory not found at $docker_root/volumes, estimating 10GB"
            volumes_size=$((10 * 1024 * 1024 * 1024))
        fi
    else
        log_warn "Docker not found, estimating 10GB for backup size"
        volumes_size=$((10 * 1024 * 1024 * 1024))
    fi
    
    log_info "Calculated volumes size: $volumes_size bytes"
    
    # Calculate required space (100% of volumes size + 5GB buffer for compression overhead)
    # Note: Backups are compressed but we need working space during compression
    local required_space=$(( volumes_size + 5 * 1024 * 1024 * 1024 ))
    log_info "Required space: $required_space bytes (100% of volumes + 5GB buffer)"
    
    # Ensure temp directory parent exists for df check
    local temp_parent=$(dirname "$TEMP_BACKUP_DIR")
    if [[ ! -d "$temp_parent" ]]; then
        log_info "Creating temp directory parent: $temp_parent"
        mkdir -p "$temp_parent" || {
            log_error "Failed to create temp directory parent: $temp_parent"
            exit 1
        }
    fi
    
    # Get available space on temp directory filesystem (in KB, convert to bytes)
    log_info "Checking available space on: $temp_parent"
    local available_kb=$(df -k "$temp_parent" 2>/dev/null | tail -1 | awk '{print $4}')
    
    if [[ -z "$available_kb" ]]; then
        log_error "Could not determine available disk space for $temp_parent"
        exit 1
    fi
    
    local available_space=$((available_kb * 1024))
    log_info "Available space: $available_space bytes"
    
    # Format sizes for human readable output
    local volumes_human=$(numfmt --to=iec-i --suffix=B $volumes_size 2>/dev/null || echo "$volumes_size bytes")
    local required_human=$(numfmt --to=iec-i --suffix=B $required_space 2>/dev/null || echo "$required_space bytes")
    local available_human=$(numfmt --to=iec-i --suffix=B $available_space 2>/dev/null || echo "$available_space bytes")
    
    log_info "Docker volumes size: $volumes_human"
    log_info "Required free space: $required_human"
    log_info "Available space: $available_human"
    
    if [[ $available_space -lt $required_space ]]; then
        log_error "Insufficient disk space!"
        log_error "Required: $required_human"
        log_error "Available: $available_human"
        log_error "Please free up space or change TEMP_BACKUP_DIR to a filesystem with more space"
        exit 1
    fi
    
    log_info "Disk space check passed"
}

###############################################################################
# Backup Execution
###############################################################################

perform_backup() {
    log_info "Starting mailcow backup process..."
    
    # Clean up any leftover backup containers from previous runs
    if docker ps -a --format '{{.Names}}' | grep -q '^mailcow-backup$'; then
        log_info "Removing leftover mailcow-backup container..."
        docker rm -f mailcow-backup >/dev/null 2>&1 || true
    fi
    
    # Create temporary backup directory
    mkdir -p "$TEMP_BACKUP_DIR"
    
    # Change to mailcow directory
    cd "$MAILCOW_PATH" || {
        log_error "Failed to change to mailcow directory: $MAILCOW_PATH"
        exit 1
    }
    
    # Check if backup script exists
    if [[ ! -f "helper-scripts/backup_and_restore.sh" ]]; then
        log_error "Mailcow backup script not found at: $MAILCOW_PATH/helper-scripts/backup_and_restore.sh"
        exit 1
    fi
    
    # Run mailcow backup script
    log_info "Running mailcow backup (components: $BACKUP_COMPONENTS, threads: $THREADS)..."
    
    export MAILCOW_BACKUP_LOCATION="$TEMP_BACKUP_DIR"
    export THREADS="$THREADS"
    
    # Don't use --delete-days - we handle cleanup ourselves after successful transfer
    if bash helper-scripts/backup_and_restore.sh backup $BACKUP_COMPONENTS; then
        log_info "Mailcow backup completed successfully"
    else
        log_error "Mailcow backup failed"
        exit 1
    fi
    
    # Find the created backup directory (mailcow creates mailcow-YYYY-MM-DD-HH-MM-SS directories)
    BACKUP_DIR=$(find "$TEMP_BACKUP_DIR" -maxdepth 1 -type d \( -name "mailcow-*" -o -name "mailcow_*" -o -name "backup-*" \) -printf "%T@ %p\n" 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2)
    
    # If no subdirectory found, check if backup files are directly in TEMP_BACKUP_DIR
    if [[ -z "$BACKUP_DIR" ]] || [[ ! -d "$BACKUP_DIR" ]]; then
        # Check if backup files exist directly in the temp directory
        if find "$TEMP_BACKUP_DIR" -maxdepth 1 -type f -name "*.sql.gz" -o -name "backup_*" | grep -q .; then
            log_info "Backup files created directly in: $TEMP_BACKUP_DIR"
            BACKUP_DIR="$TEMP_BACKUP_DIR"
        else
            log_error "Backup directory not found in $TEMP_BACKUP_DIR"
            log_error "Contents of $TEMP_BACKUP_DIR:"
            ls -la "$TEMP_BACKUP_DIR" 2>&1 | tee -a "${LOG_FILE:-/var/log/mailcow-backup.log}"
            exit 1
        fi
    else
        log_info "Backup created at: $BACKUP_DIR"
    fi
}

###############################################################################
# Checksum Generation
###############################################################################

generate_checksums() {
    log_info "Generating checksums for backup verification..."
    
    # Quick disk space check
    local available_space=$(df -k "$(dirname "$BACKUP_DIR")" 2>/dev/null | tail -1 | awk '{print $4 * 1024}')
    if [[ $available_space -lt $((1 * 1024 * 1024 * 1024)) ]]; then
        log_error "Low disk space detected before checksum generation"
        log_error "Available: $(numfmt --to=iec-i --suffix=B $available_space 2>/dev/null || echo "${available_space} bytes")"
        exit 1
    fi
    
    local checksum_file="${BACKUP_DIR}/checksums.sha256"
    
    # Generate SHA-256 checksums for all files in backup
    cd "$BACKUP_DIR" || exit 1
    
    if command -v sha256sum &> /dev/null; then
        find . -type f ! -name "checksums.sha256" -exec sha256sum {} \; > "$checksum_file"
    else
        log_error "sha256sum utility not found"
        exit 1
    fi
    
    log_info "Checksums generated: $checksum_file"
}

###############################################################################
# Transfer to Hetzner
###############################################################################

transfer_to_hetzner() {
    log_info "Transferring backup to Hetzner storage box..."
    
    local backup_name=$(basename "$BACKUP_DIR")
    local remote_path="${HETZNER_REMOTE_PATH}/${backup_name}"
    
    # Create remote directory if it doesn't exist
    ssh -i "$SSH_KEY_PATH" \
        -p "$HETZNER_PORT" \
        "${HETZNER_USER}@${HETZNER_HOST}" \
        "mkdir -p ${HETZNER_REMOTE_PATH}" 2>/dev/null || {
        log_error "Failed to create remote directory"
        exit 1
    }
    
    # Calculate backup size
    local backup_size=$(du -sh "$BACKUP_DIR" | cut -f1)
    log_info "Backup size: $backup_size"
    log_info "Syncing to ${HETZNER_USER}@${HETZNER_HOST}:${remote_path}"
    
    # Transfer using rsync with progress
    if rsync -avz \
             --delete \
             --info=progress2 \
             --no-inc-recursive \
             -e "ssh -i $SSH_KEY_PATH -p $HETZNER_PORT" \
             "$BACKUP_DIR/" \
             "${HETZNER_USER}@${HETZNER_HOST}:${remote_path}/" 2>&1 | \
             while IFS= read -r line; do
                 # Log important rsync output
                 if [[ "$line" =~ ^(sending|sent|total) ]] || [[ "$line" =~ [0-9]+% ]]; then
                     echo "$line"
                     log "INFO" "rsync: $line"
                 fi
             done; then
        log_info "Transfer completed successfully"
    else
        log_error "Transfer failed"
        exit 1
    fi
}

###############################################################################
# Verify Transfer
###############################################################################

verify_transfer() {
    log_info "Verifying backup integrity..."
    
    local backup_name=$(basename "$BACKUP_DIR")
    local remote_path="${HETZNER_REMOTE_PATH}/${backup_name}"
    local checksum_file="checksums.sha256"
    
    # Download remote checksums
    local remote_checksums=$(ssh -i "$SSH_KEY_PATH" \
                                 -p "$HETZNER_PORT" \
                                 "${HETZNER_USER}@${HETZNER_HOST}" \
                                 "cat ${remote_path}/${checksum_file}" 2>/dev/null)
    
    if [[ -z "$remote_checksums" ]]; then
        log_error "Failed to retrieve remote checksums"
        exit 1
    fi
    
    # Compare with local checksums
    local local_checksums=$(cat "${BACKUP_DIR}/${checksum_file}")
    
    if [[ "$local_checksums" == "$remote_checksums" ]]; then
        log_info "Verification successful - checksums match"
    else
        log_error "Verification failed - checksums do not match"
        exit 1
    fi
}

###############################################################################
# Remote Storage Statistics
###############################################################################

get_remote_storage_stats() {
    # Note: No log_info here - output goes to stdout and would be captured with the return value
    
    local backup_name="$1"
    local ssh_opts="-i $SSH_KEY_PATH -p $HETZNER_PORT -o BatchMode=yes -o ConnectTimeout=10"
    local ssh_target="${HETZNER_USER}@${HETZNER_HOST}"
    
    # Hetzner Storage Box has a restricted shell - run simple commands and process locally
    
    # Get backup size
    local backup_size=$(ssh $ssh_opts "$ssh_target" "du -sh ${HETZNER_REMOTE_PATH}/${backup_name}" 2>/dev/null | cut -f1)
    backup_size="${backup_size:-N/A}"
    
    # Get total used space
    local total_used=$(ssh $ssh_opts "$ssh_target" "du -sh ${HETZNER_REMOTE_PATH}/" 2>/dev/null | cut -f1)
    total_used="${total_used:-N/A}"
    
    # Get backup count
    local backup_count=$(ssh $ssh_opts "$ssh_target" "ls -1 ${HETZNER_REMOTE_PATH}/" 2>/dev/null | grep -c "^mailcow-" || echo "0")
    
    # Get df info and parse locally
    local df_output=$(ssh $ssh_opts "$ssh_target" "df -h" 2>/dev/null | tail -1)
    local total_size=$(echo "$df_output" | awk '{print $2}')
    local total_avail=$(echo "$df_output" | awk '{print $4}')
    local use_percent=$(echo "$df_output" | awk '{print $5}')
    
    total_size="${total_size:-N/A}"
    total_avail="${total_avail:-N/A}"
    use_percent="${use_percent:-N/A}"
    
    # Return pipe-separated values
    echo "${backup_size}|${total_used}|${total_avail}|${total_size}|${use_percent}|${backup_count}"
}

###############################################################################
# Cleanup Old Remote Backups
###############################################################################

cleanup_old_remote_backups() {
    log_info "Checking for old remote backups to remove..."
    
    # List remote directories (sorted chronologically by name)
    local remote_dirs=$(ssh -i "$SSH_KEY_PATH" \
        -p "$HETZNER_PORT" \
        "${HETZNER_USER}@${HETZNER_HOST}" \
        "ls -1 ${HETZNER_REMOTE_PATH}" 2>/dev/null | grep "^mailcow-" | sort || true)
    
    if [[ -z "$remote_dirs" ]]; then
        log_info "No remote backups found"
        return
    fi
    
    local total_backups=$(echo "$remote_dirs" | wc -l)
    log_info "Found $total_backups remote backup(s)"
    
    # --- Phase 1: Remove backups older than retention period ---
    log_info "Removing remote backups older than $REMOTE_RETENTION_DAYS days..."
    
    local cutoff_date=$(date -d "$REMOTE_RETENTION_DAYS days ago" +%Y-%m-%d 2>/dev/null || date -v-${REMOTE_RETENTION_DAYS}d +%Y-%m-%d 2>/dev/null)
    
    if [[ -z "$cutoff_date" ]]; then
        log_warn "Could not determine cutoff date for remote cleanup"
        return
    fi
    
    log_info "Cutoff date: $cutoff_date (removing backups before this date)"
    
    local removed_count=0
    while IFS= read -r backup_dir; do
        if [[ "$backup_dir" =~ mailcow-([0-9]{4}-[0-9]{2}-[0-9]{2}) ]]; then
            local backup_date="${BASH_REMATCH[1]}"
            
            if [[ "$backup_date" < "$cutoff_date" ]]; then
                log_info "Removing expired remote backup: $backup_dir (date: $backup_date)"
                if ssh -i "$SSH_KEY_PATH" \
                       -p "$HETZNER_PORT" \
                       "${HETZNER_USER}@${HETZNER_HOST}" \
                       "rm -rf ${HETZNER_REMOTE_PATH}/${backup_dir}" 2>/dev/null; then
                    removed_count=$((removed_count + 1))
                else
                    log_warn "Failed to remove $backup_dir"
                fi
            fi
        fi
    done <<< "$remote_dirs"
    
    if [[ $removed_count -gt 0 ]]; then
        log_info "Removed $removed_count expired remote backup(s)"
    else
        log_info "No expired remote backups to remove"
    fi
    
    # --- Phase 2: Keep only one backup per day (latest), remove duplicates ---
    log_info "Checking for duplicate backups (keeping latest per day)..."
    
    # Re-list after retention cleanup
    remote_dirs=$(ssh -i "$SSH_KEY_PATH" \
        -p "$HETZNER_PORT" \
        "${HETZNER_USER}@${HETZNER_HOST}" \
        "ls -1 ${HETZNER_REMOTE_PATH}" 2>/dev/null | grep "^mailcow-" | sort || true)
    
    if [[ -z "$remote_dirs" ]]; then
        return
    fi
    
    local prev_date=""
    local prev_dir=""
    local dedup_count=0
    local dirs_to_remove=()
    
    # Collect all directories grouped by date; since they're sorted, the last
    # entry for each date is the latest backup of that day
    while IFS= read -r backup_dir; do
        if [[ "$backup_dir" =~ mailcow-([0-9]{4}-[0-9]{2}-[0-9]{2}) ]]; then
            local this_date="${BASH_REMATCH[1]}"
            
            if [[ "$this_date" == "$prev_date" ]] && [[ -n "$prev_dir" ]]; then
                # Same date as previous - mark the OLDER (previous) one for removal
                dirs_to_remove+=("$prev_dir")
            fi
            
            prev_date="$this_date"
            prev_dir="$backup_dir"
        fi
    done <<< "$remote_dirs"
    
    for dir_to_remove in "${dirs_to_remove[@]+${dirs_to_remove[@]}}"; do
        [[ -z "$dir_to_remove" ]] && continue
        log_info "Removing duplicate backup: $dir_to_remove"
        if ssh -i "$SSH_KEY_PATH" \
               -p "$HETZNER_PORT" \
               "${HETZNER_USER}@${HETZNER_HOST}" \
               "rm -rf ${HETZNER_REMOTE_PATH}/${dir_to_remove}" 2>/dev/null; then
            dedup_count=$((dedup_count + 1))
        else
            log_warn "Failed to remove duplicate $dir_to_remove"
        fi
    done
    
    if [[ $dedup_count -gt 0 ]]; then
        log_info "Removed $dedup_count duplicate remote backup(s)"
    else
        log_info "No duplicate backups found"
    fi
}

###############################################################################
# Main Execution
###############################################################################

main() {
    log_info "========================================="
    log_info "Mailcow Backup to Hetzner - Starting"
    log_info "========================================="
    
    # Acquire lock
    acquire_lock
    
    # Load configuration
    load_config
    
    # Validate SSH connection
    test_ssh_connection
    
    # Remove and recreate temp backup directory - ensures clean slate and maximum disk space
    if [[ -d "$TEMP_BACKUP_DIR" ]]; then
        log_info "Removing temp backup directory: $TEMP_BACKUP_DIR"
        rm -rf "${TEMP_BACKUP_DIR:?}"
    fi
    mkdir -p "$TEMP_BACKUP_DIR"
    log_info "Temp backup directory ready: $TEMP_BACKUP_DIR"
    
    # Check disk space
    check_disk_space
    
    # Perform backup
    perform_backup
    
    # Capture backup size while files still exist locally
    BACKUP_SIZE=$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)
    BACKUP_SIZE="${BACKUP_SIZE:-unknown}"
    log_info "Backup size: $BACKUP_SIZE"
    
    # Generate checksums
    generate_checksums
    
    # Transfer to Hetzner
    transfer_to_hetzner
    
    # Verify transfer
    verify_transfer
    
    # Capture backup name for reporting
    local backup_name=$(basename "$BACKUP_DIR")
    
    # Remove local backup now that it is safely on Hetzner
    if [[ -d "$TEMP_BACKUP_DIR" ]]; then
        log_info "Removing local temp directory: $TEMP_BACKUP_DIR"
        rm -rf "${TEMP_BACKUP_DIR:?}"
        if [[ -d "$TEMP_BACKUP_DIR" ]]; then
            log_warn "Failed to remove temp directory: $TEMP_BACKUP_DIR"
            log_warn "Contents: $(ls -la "$TEMP_BACKUP_DIR" 2>&1)"
        else
            log_info "Local cleanup successful"
        fi
    fi
    
    # Cleanup old remote backups based on retention policy
    cleanup_old_remote_backups
    
    # Gather remote storage statistics
    log_info "Gathering remote storage statistics..."
    local remote_stats=$(get_remote_storage_stats "$backup_name")
    local remote_backup_size=$(echo "$remote_stats" | cut -d'|' -f1)
    local remote_total_used=$(echo "$remote_stats" | cut -d'|' -f2)
    local remote_total_avail=$(echo "$remote_stats" | cut -d'|' -f3)
    local remote_total_size=$(echo "$remote_stats" | cut -d'|' -f4)
    local remote_use_percent=$(echo "$remote_stats" | cut -d'|' -f5)
    local remote_backup_count=$(echo "$remote_stats" | cut -d'|' -f6)
    
    log_info "========================================="
    log_info "Backup completed successfully!"
    log_info "========================================="
    
    # Send success notification with detailed statistics
    local hostname=$(hostname -f 2>/dev/null || hostname)
    send_notification "success" \
        "$backup_name" \
        "$BACKUP_SIZE" \
        "$hostname" \
        "${HETZNER_REMOTE_PATH}/" \
        "$remote_backup_count" \
        "$remote_total_used" \
        "$remote_total_size" \
        "$remote_use_percent" \
        "$remote_total_avail"
}

# Error handler for failure notifications
handle_error() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        send_notification "failure" "Backup failed with exit code: $exit_code
Check log file for details: ${LOG_FILE}"
    fi
    release_lock
    exit $exit_code
}

# Set up error trap
trap handle_error ERR EXIT

# Run main function
main "$@"

# Remove trap on successful completion
trap - ERR EXIT
