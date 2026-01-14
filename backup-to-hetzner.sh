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

# Color codes for output
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
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${LOG_FILE:-/var/log/mailcow-backup.log}"
}

log_info() {
    log "INFO" "$@"
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    log "WARN" "$@"
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    log "ERROR" "$@"
    echo -e "${RED}[ERROR]${NC} $*" >&2
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
    
    # Calculate required space (50% of volumes size + 2GB buffer)
    local required_space=$(( volumes_size / 2 + 2 * 1024 * 1024 * 1024 ))
    log_info "Required space: $required_space bytes"
    
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
    
    # Find the created backup directory
    BACKUP_DIR=$(find "$TEMP_BACKUP_DIR" -maxdepth 1 -type d -name "mailcow_*" -printf "%T@ %p\n" | sort -n | tail -1 | cut -d' ' -f2)
    
    if [[ -z "$BACKUP_DIR" ]] || [[ ! -d "$BACKUP_DIR" ]]; then
        log_error "Backup directory not found in $TEMP_BACKUP_DIR"
        exit 1
    fi
    
    log_info "Backup created at: $BACKUP_DIR"
}

###############################################################################
# Checksum Generation
###############################################################################

generate_checksums() {
    log_info "Generating checksums for backup verification..."
    
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
    
    # Transfer using rsync
    log_info "Syncing to ${HETZNER_USER}@${HETZNER_HOST}:${remote_path}"
    
    if rsync -avz \
             --delete \
             -e "ssh -i $SSH_KEY_PATH -p $HETZNER_PORT" \
             "$BACKUP_DIR/" \
             "${HETZNER_USER}@${HETZNER_HOST}:${remote_path}/"; then
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
    log_info "Cleaning up old backups..."
    
    # Clean local backups
    log_info "Removing local backups older than $LOCAL_RETENTION_DAYS days..."
    find "$TEMP_BACKUP_DIR" -maxdepth 1 -type d -name "mailcow_*" -mtime +"$LOCAL_RETENTION_DAYS" -exec rm -rf {} \; 2>/dev/null || true
    
    # Clean remote backups
    log_info "Removing remote backups older than $REMOTE_RETENTION_DAYS days..."
    ssh -i "$SSH_KEY_PATH" \
        -p "$HETZNER_PORT" \
        "${HETZNER_USER}@${HETZNER_HOST}" \
        "find ${HETZNER_REMOTE_PATH} -maxdepth 1 -type d -name 'mailcow_*' -mtime +${REMOTE_RETENTION_DAYS} -exec rm -rf {} \;" 2>/dev/null || {
        log_warn "Failed to clean remote backups (non-critical)"
    }
    
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
    
    # Cleanup old backups
    cleanup_old_backups
    
    log_info "========================================="
    log_info "Backup completed successfully!"
    log_info "========================================="
}

# Run main function
main "$@"
