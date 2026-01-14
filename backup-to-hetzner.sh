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
    LOCAL_RETENTION_DAYS="${LOCAL_RETENTION_DAYS:-7}"
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
    local message="$2"
    
    # Skip if notifications disabled
    if [[ "${EMAIL_NOTIFICATIONS:-false}" != "true" ]]; then
        return 0
    fi
    
    if [[ -z "${NOTIFICATION_EMAIL}" ]]; then
        log_warn "Email notifications enabled but NOTIFICATION_EMAIL not set"
        return 1
    fi
    
    local subject
    local body
    local hostname=$(hostname -f 2>/dev/null || hostname)
    local from_addr="${NOTIFICATION_FROM:-mailcow-backup@${hostname}}"
    
    if [[ "$status" == "success" ]]; then
        subject="✓ Mailcow Backup Successful - $hostname"
        body="Mailcow backup completed successfully on $hostname at $(date '+%Y-%m-%d %H:%M:%S')

Backup Details:
${message}

Log file: ${LOG_FILE}

---
Mailcow Cold Standby Backup System
https://github.com/Paul1404/mailcow-cold-standby"
    else
        subject="✗ Mailcow Backup Failed - $hostname"
        body="Mailcow backup FAILED on $hostname at $(date '+%Y-%m-%d %H:%M:%S')

Error Details:
${message}

Please check the log file: ${LOG_FILE}

---
Mailcow Cold Standby Backup System
https://github.com/Paul1404/mailcow-cold-standby"
    fi
    
    # Use mailcow's SMTP directly on localhost:25
    # This is the recommended approach per mailcow community
    if command -v nc &> /dev/null || command -v netcat &> /dev/null; then
        local nc_cmd=$(command -v nc || command -v netcat)
        
        log_info "Sending email notification via mailcow SMTP (localhost:25)..."
        
        # Send email via SMTP using netcat
        {
            echo "EHLO ${hostname}"
            sleep 0.5
            echo "MAIL FROM:<${from_addr}>"
            sleep 0.5
            echo "RCPT TO:<${NOTIFICATION_EMAIL}>"
            sleep 0.5
            echo "DATA"
            sleep 0.5
            echo "From: ${from_addr}"
            echo "To: ${NOTIFICATION_EMAIL}"
            echo "Subject: ${subject}"
            echo "Date: $(date -R)"
            echo ""
            echo "${body}"
            echo "."
            sleep 0.5
            echo "QUIT"
        } | $nc_cmd localhost 25 > /dev/null 2>&1 && \
            log_info "Email notification sent to $NOTIFICATION_EMAIL" && return 0
    fi
    
    # Fallback to swaks (can connect directly to mailcow SMTP)
    if command -v swaks &> /dev/null; then
        swaks --to "$NOTIFICATION_EMAIL" \
              --from "$from_addr" \
              --server localhost:25 \
              --subject "$subject" \
              --body "$body" \
              --silent 2 2>/dev/null && \
            log_info "Email notification sent to $NOTIFICATION_EMAIL via swaks" && return 0
    fi
    
    # Fallback to mail command
    if command -v mail &> /dev/null; then
        echo "$body" | mail -s "$subject" -r "$from_addr" "$NOTIFICATION_EMAIL" 2>/dev/null && \
            log_info "Email notification sent to $NOTIFICATION_EMAIL via mail" && return 0
    fi
    
    log_warn "Could not send email notification - netcat/nc, swaks, or mail command required"
    log_warn "Install netcat: dnf install -y nmap-ncat"
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
    
    # Clean up temp directory to free space
    if [[ -d "$TEMP_BACKUP_DIR" ]]; then
        log_info "Cleaning up old temp backups to free space..."
        rm -rf "${TEMP_BACKUP_DIR:?}"/mailcow-* 2>/dev/null || true
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
    
    if bash helper-scripts/backup_and_restore.sh backup $BACKUP_COMPONENTS --delete-days "$LOCAL_RETENTION_DAYS"; then
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
# Cleanup Old Backups
###############################################################################

cleanup_old_backups() {
    local backup_dir_to_remove="$1"
    log_info "Cleaning up old backups..."
    
    # Clean up the current backup from local temp after successful transfer
    # SAFETY CHECKS before rm -rf:
    # 1. Variable must not be empty
    # 2. Must be a directory
    # 3. Must be under TEMP_BACKUP_DIR
    # 4. Must contain "mailcow" in the path
    # 5. Must not be a system directory
    if [[ -z "$backup_dir_to_remove" ]]; then
        log_warn "No backup directory provided for cleanup"
        return 1
    fi
    
    if [[ ! -d "$backup_dir_to_remove" ]]; then
        log_warn "Backup directory doesn't exist: $backup_dir_to_remove"
        return 1
    fi
    
    # Ensure the path is under TEMP_BACKUP_DIR and contains "mailcow"
    if [[ "$backup_dir_to_remove" != "$TEMP_BACKUP_DIR"/* ]] || [[ "$backup_dir_to_remove" != *mailcow* ]]; then
        log_error "SAFETY CHECK FAILED: Path doesn't match expected pattern: $backup_dir_to_remove"
        log_error "Expected path under: $TEMP_BACKUP_DIR and containing 'mailcow'"
        return 1
    fi
    
    # Prevent deletion of critical directories
    case "$backup_dir_to_remove" in
        /|/root|/home|/etc|/usr|/var|/boot|/sys|/proc|/dev)
            log_error "SAFETY CHECK FAILED: Refusing to delete system directory: $backup_dir_to_remove"
            return 1
            ;;
    esac
    
    log_info "Removing local backup after successful transfer: $backup_dir_to_remove"
    if rm -rf "${backup_dir_to_remove:?}"; then
        log_info "Successfully removed local backup"
    else
        log_warn "Failed to remove local backup: $backup_dir_to_remove"
        return 1
    fi
    
    # Clean other old local backups based on retention
    log_info "Removing local backups older than $LOCAL_RETENTION_DAYS days..."
    find "$TEMP_BACKUP_DIR" -maxdepth 1 -type d \( -name "mailcow-*" -o -name "mailcow_*" \) -mtime +"$LOCAL_RETENTION_DAYS" -exec rm -rf {} \; 2>/dev/null || true
    
    # Clean remote backups
    log_info "Removing remote backups older than $REMOTE_RETENTION_DAYS days..."
    
    # Calculate cutoff date in format YYYY-MM-DD
    local cutoff_date=$(date -d "$REMOTE_RETENTION_DAYS days ago" +%Y-%m-%d 2>/dev/null || date -v-${REMOTE_RETENTION_DAYS}d +%Y-%m-%d 2>/dev/null)
    
    if [[ -z "$cutoff_date" ]]; then
        log_warn "Could not determine cutoff date for remote cleanup"
        log_info "Cleanup completed"
        return
    fi
    
    log_info "Cutoff date: $cutoff_date (removing backups older than this)"
    
    # List remote directories and process locally
    local remote_dirs=$(ssh -i "$SSH_KEY_PATH" \
        -p "$HETZNER_PORT" \
        "${HETZNER_USER}@${HETZNER_HOST}" \
        "ls -1 ${HETZNER_REMOTE_PATH}" 2>/dev/null | grep "^mailcow-" || true)
    
    if [[ -z "$remote_dirs" ]]; then
        log_info "No remote backups found to clean"
        log_info "Cleanup completed"
        return
    fi
    
    local removed_count=0
    while IFS= read -r backup_dir; do
        # Extract date from directory name (mailcow-YYYY-MM-DD-HH-MM-SS)
        if [[ "$backup_dir" =~ mailcow-([0-9]{4}-[0-9]{2}-[0-9]{2}) ]]; then
            local backup_date="${BASH_REMATCH[1]}"
            
            # Compare dates (lexicographically works for YYYY-MM-DD format)
            if [[ "$backup_date" < "$cutoff_date" ]]; then
                log_info "Removing old remote backup: $backup_dir (date: $backup_date)"
                if ssh -i "$SSH_KEY_PATH" \
                       -p "$HETZNER_PORT" \
                       "${HETZNER_USER}@${HETZNER_HOST}" \
                       "rm -rf ${HETZNER_REMOTE_PATH}/${backup_dir}" 2>/dev/null; then
                    ((removed_count++))
                else
                    log_warn "Failed to remove $backup_dir"
                fi
            fi
        fi
    done <<< "$remote_dirs"
    
    if [[ $removed_count -eq 0 ]]; then
        log_info "No old remote backups to remove"
    else
        log_info "Removed $removed_count old remote backup(s)"
    fi
    
    log_info "Cleanup completed"
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
    
    # Check disk space
    check_disk_space
    
    # Perform backup
    perform_backup
    
    # Generate checksums
    generate_checksums
    
    # Transfer to Hetzner
    transfer_to_hetzner
    
    # Verify transfer
    verify_transfer
    
    # Cleanup old backups (pass the backup directory path)
    cleanup_old_backups "$BACKUP_DIR"
    
    log_info "========================================="
    log_info "Backup completed successfully!"
    log_info "========================================="
    
    # Send success notification
    local backup_name=$(basename "$BACKUP_DIR")
    local backup_size=$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1 || echo "unknown")
    send_notification "success" "Backup: $backup_name
Size: $backup_size
Location: ${HETZNER_USER}@${HETZNER_HOST}:${HETZNER_REMOTE_PATH}/$backup_name"
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
