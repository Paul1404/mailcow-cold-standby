#!/bin/bash

###############################################################################
# Mailcow Restore from Hetzner Storage Box
# 
# This script restores a mailcow backup from Hetzner storage box.
# It downloads the selected backup, verifies integrity, and restores mailcow.
#
# Author: Paul Dresch
# License: MIT
###############################################################################

set -euo pipefail

# Configuration file path
CONFIG_FILE="/etc/mailcow-backup/.env"
RESTORE_LOG="/var/log/mailcow-restore.log"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

###############################################################################
# Logging Functions
###############################################################################

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$RESTORE_LOG"
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
# Configuration Loading
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
    
    log_info "Configuration loaded successfully"
}

###############################################################################
# SSH Connection Test
###############################################################################

test_ssh_connection() {
    log_info "Testing SSH connection to Hetzner storage box..."
    
    if [[ ! -f "$SSH_KEY_PATH" ]]; then
        log_error "SSH key not found: $SSH_KEY_PATH"
        exit 1
    fi
    
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
# List Available Backups
###############################################################################

list_backups() {
    log_info "Retrieving list of available backups..."
    
    # Get list of backup directories
    local backups=$(ssh -i "$SSH_KEY_PATH" \
                        -p "$HETZNER_PORT" \
                        "${HETZNER_USER}@${HETZNER_HOST}" \
                        "ls -1 ${HETZNER_REMOTE_PATH} 2>/dev/null | grep '^mailcow_'" 2>/dev/null)
    
    if [[ -z "$backups" ]]; then
        log_error "No backups found on Hetzner storage box"
        exit 1
    fi
    
    echo ""
    echo -e "${BLUE}Available backups:${NC}"
    echo "=================="
    
    local count=1
    declare -g -A BACKUP_MAP
    
    while IFS= read -r backup; do
        # Get backup size
        local size=$(ssh -i "$SSH_KEY_PATH" \
                         -p "$HETZNER_PORT" \
                         "${HETZNER_USER}@${HETZNER_HOST}" \
                         "du -sh ${HETZNER_REMOTE_PATH}/${backup} 2>/dev/null | cut -f1" 2>/dev/null)
        
        # Extract date from backup name (mailcow_YYYY-MM-DD_HH-MM-SS)
        local date_part=$(echo "$backup" | sed 's/mailcow_//')
        
        echo -e "${count}. ${GREEN}${backup}${NC} - ${YELLOW}${size}${NC} - ${date_part}"
        BACKUP_MAP[$count]="$backup"
        ((count++))
    done <<< "$backups"
    
    echo ""
}

###############################################################################
# Select Backup
###############################################################################

select_backup() {
    local max_num=${#BACKUP_MAP[@]}
    local selection
    
    while true; do
        echo -n "Enter backup number to restore (1-${max_num}) or 'q' to quit: "
        read -r selection
        
        if [[ "$selection" == "q" ]] || [[ "$selection" == "Q" ]]; then
            log_info "Restore cancelled by user"
            exit 0
        fi
        
        if [[ "$selection" =~ ^[0-9]+$ ]] && [[ "$selection" -ge 1 ]] && [[ "$selection" -le "$max_num" ]]; then
            SELECTED_BACKUP="${BACKUP_MAP[$selection]}"
            log_info "Selected backup: $SELECTED_BACKUP"
            break
        else
            echo -e "${RED}Invalid selection. Please try again.${NC}"
        fi
    done
}

###############################################################################
# Confirm Restore
###############################################################################

confirm_restore() {
    echo ""
    echo -e "${RED}WARNING: This will stop mailcow and restore from backup!${NC}"
    echo -e "${RED}All current data will be replaced with the backup data.${NC}"
    echo ""
    echo -n "Are you sure you want to continue? (yes/no): "
    read -r confirmation
    
    if [[ "$confirmation" != "yes" ]]; then
        log_info "Restore cancelled by user"
        exit 0
    fi
}

###############################################################################
# Check Disk Space
###############################################################################

check_disk_space() {
    log_info "Checking disk space for restore..."
    
    # Get backup size
    local backup_size=$(ssh -i "$SSH_KEY_PATH" \
                            -p "$HETZNER_PORT" \
                            "${HETZNER_USER}@${HETZNER_HOST}" \
                            "du -sb ${HETZNER_REMOTE_PATH}/${SELECTED_BACKUP} 2>/dev/null | cut -f1" 2>/dev/null)
    
    if [[ -z "$backup_size" ]]; then
        log_warn "Could not determine backup size, skipping disk space check"
        return
    fi
    
    # Get available space
    local restore_dir="/tmp/mailcow-restore"
    local available_space=$(df /tmp | tail -1 | awk '{print $4 * 1024}')
    
    # Require 2x backup size for safety
    local required_space=$((backup_size * 2))
    
    log_info "Backup size: $(numfmt --to=iec-i --suffix=B $backup_size)"
    log_info "Required space: $(numfmt --to=iec-i --suffix=B $required_space)"
    log_info "Available space: $(numfmt --to=iec-i --suffix=B $available_space)"
    
    if [[ $available_space -lt $required_space ]]; then
        log_error "Insufficient disk space for restore!"
        exit 1
    fi
    
    log_info "Disk space check passed"
}

###############################################################################
# Download Backup
###############################################################################

download_backup() {
    log_info "Downloading backup from Hetzner..."
    
    local restore_dir="/tmp/mailcow-restore"
    local backup_path="${restore_dir}/${SELECTED_BACKUP}"
    
    # Create restore directory
    mkdir -p "$backup_path"
    
    # Download using rsync
    log_info "Downloading ${SELECTED_BACKUP}..."
    
    if rsync -avz \
             --progress \
             -e "ssh -i $SSH_KEY_PATH -p $HETZNER_PORT" \
             "${HETZNER_USER}@${HETZNER_HOST}:${HETZNER_REMOTE_PATH}/${SELECTED_BACKUP}/" \
             "$backup_path/"; then
        log_info "Download completed successfully"
        RESTORE_PATH="$backup_path"
    else
        log_error "Download failed"
        exit 1
    fi
}

###############################################################################
# Verify Backup Integrity
###############################################################################

verify_backup() {
    log_info "Verifying backup integrity..."
    
    local checksum_file="${RESTORE_PATH}/checksums.sha256"
    
    if [[ ! -f "$checksum_file" ]]; then
        log_warn "Checksum file not found, skipping verification"
        return
    fi
    
    cd "$RESTORE_PATH" || exit 1
    
    # Verify checksums
    if command -v sha256sum &> /dev/null; then
        if sha256sum -c "$checksum_file" 2>&1 | tee -a "$RESTORE_LOG"; then
            log_info "Backup integrity verified successfully"
        else
            log_error "Backup integrity check failed!"
            exit 1
        fi
    else
        log_warn "sha256sum utility not found, skipping integrity check"
    fi
}

###############################################################################
# Stop Mailcow
###############################################################################

stop_mailcow() {
    log_info "Stopping mailcow containers..."
    
    cd "$MAILCOW_PATH" || {
        log_error "Failed to change to mailcow directory: $MAILCOW_PATH"
        exit 1
    }
    
    if docker compose down; then
        log_info "Mailcow stopped successfully"
    else
        log_error "Failed to stop mailcow"
        exit 1
    fi
}

###############################################################################
# Restore Mailcow
###############################################################################

restore_mailcow() {
    log_info "Restoring mailcow from backup..."
    
    cd "$MAILCOW_PATH" || exit 1
    
    # Check if restore script exists
    if [[ ! -f "helper-scripts/backup_and_restore.sh" ]]; then
        log_error "Mailcow restore script not found"
        exit 1
    fi
    
    # Set backup location
    export MAILCOW_BACKUP_LOCATION="$(dirname "$RESTORE_PATH")"
    
    # Restore using mailcow's script
    log_info "Running mailcow restore from: $RESTORE_PATH"
    
    if bash helper-scripts/backup_and_restore.sh restore; then
        log_info "Mailcow restore completed successfully"
    else
        log_error "Mailcow restore failed"
        exit 1
    fi
}

###############################################################################
# Start Mailcow
###############################################################################

start_mailcow() {
    log_info "Starting mailcow containers..."
    
    cd "$MAILCOW_PATH" || exit 1
    
    if docker compose up -d; then
        log_info "Mailcow started successfully"
    else
        log_error "Failed to start mailcow"
        exit 1
    fi
    
    log_info "Waiting for services to become ready..."
    sleep 10
    
    # Show status
    docker compose ps
}

###############################################################################
# Cleanup
###############################################################################

cleanup() {
    log_info "Cleaning up temporary files..."
    
    if [[ -n "${RESTORE_PATH:-}" ]] && [[ -d "$RESTORE_PATH" ]]; then
        rm -rf "$RESTORE_PATH"
        log_info "Temporary files removed"
    fi
}

###############################################################################
# Main Execution
###############################################################################

main() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}Mailcow Restore from Hetzner${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo ""
    
    # Load configuration
    load_config
    
    # Test SSH connection
    test_ssh_connection
    
    # List available backups
    list_backups
    
    # Select backup
    select_backup
    
    # Confirm restore
    confirm_restore
    
    # Check disk space
    check_disk_space
    
    # Download backup
    download_backup
    
    # Verify integrity
    verify_backup
    
    # Stop mailcow
    stop_mailcow
    
    # Restore mailcow
    restore_mailcow
    
    # Start mailcow
    start_mailcow
    
    # Cleanup
    cleanup
    
    echo ""
    log_info "========================================="
    log_info "Restore completed successfully!"
    log_info "========================================="
    echo ""
    log_info "Please verify that all services are running correctly."
    log_info "Check the mailcow web interface and test mail functionality."
}

# Run main function
main "$@"
