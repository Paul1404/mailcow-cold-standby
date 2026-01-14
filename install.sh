#!/bin/bash

###############################################################################
# Mailcow Backup to Hetzner - Installation Script
# 
# This script installs the mailcow backup solution for Hetzner storage boxes.
# It checks prerequisites, installs dependencies, configures the system, and
# sets up systemd timer for automated backups.
#
# Author: Paul Dresch
# License: MIT
###############################################################################

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Installation paths
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/mailcow-backup"
SYSTEMD_DIR="/etc/systemd/system"

###############################################################################
# Helper Functions
###############################################################################

print_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

print_header() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}$*${NC}"
    echo -e "${BLUE}=========================================${NC}"
}

###############################################################################
# Check Prerequisites
###############################################################################

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        exit 1
    fi
    print_info "Running as root ✓"
}

check_mailcow() {
    print_info "Searching for mailcow installation..."
    
    local mailcow_paths=(
        "/opt/mailcow-dockerized"
        "/srv/mailcow-dockerized"
        "/var/mailcow-dockerized"
        "/home/mailcow-dockerized"
    )
    
    DETECTED_MAILCOW_PATH=""
    
    for path in "${mailcow_paths[@]}"; do
        if [[ -f "$path/docker-compose.yml" ]] || [[ -f "$path/compose.yaml" ]]; then
            if [[ -f "$path/helper-scripts/backup_and_restore.sh" ]]; then
                DETECTED_MAILCOW_PATH="$path"
                print_info "Found mailcow installation at: $path ✓"
                break
            fi
        fi
    done
    
    if [[ -z "$DETECTED_MAILCOW_PATH" ]]; then
        print_error "Mailcow installation not found in standard locations"
        echo -n "Enter mailcow installation path manually: "
        read -r custom_path
        
        if [[ -f "$custom_path/helper-scripts/backup_and_restore.sh" ]]; then
            DETECTED_MAILCOW_PATH="$custom_path"
            print_info "Using mailcow at: $DETECTED_MAILCOW_PATH"
        else
            print_error "Invalid mailcow path: $custom_path"
            exit 1
        fi
    fi
    
    # Confirm with user
    echo -n "Use mailcow installation at $DETECTED_MAILCOW_PATH? (yes/no): "
    read -r confirm
    if [[ "$confirm" != "yes" ]]; then
        print_error "Installation cancelled"
        exit 1
    fi
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        exit 1
    fi
    print_info "Docker found ✓"
    
    if ! command -v docker compose &> /dev/null; then
        print_warn "Docker Compose plugin not found, checking for standalone..."
        if ! command -v docker-compose &> /dev/null; then
            print_error "Docker Compose is not installed"
            exit 1
        fi
        print_info "Docker Compose (standalone) found ✓"
    else
        print_info "Docker Compose found ✓"
    fi
}

install_dependencies() {
    print_info "Checking dependencies..."
    
    local packages_to_install=()
    
    # Check rsync
    if ! command -v rsync &> /dev/null; then
        print_warn "rsync not found, will install"
        packages_to_install+=("rsync")
    else
        print_info "rsync found ✓"
    fi
    
    # Check sha256sum (should be available on all modern Linux systems)
    if ! command -v sha256sum &> /dev/null; then
        print_error "sha256sum not found. This should be available by default."
        exit 1
    else
        print_info "sha256sum found ✓"
    fi
    
    # Install missing packages
    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        print_info "Installing packages: ${packages_to_install[*]}"
        
        # Detect package manager
        if command -v dnf &> /dev/null; then
            dnf install -y "${packages_to_install[@]}"
        elif command -v yum &> /dev/null; then
            yum install -y "${packages_to_install[@]}"
        elif command -v apt-get &> /dev/null; then
            apt-get update
            apt-get install -y "${packages_to_install[@]}"
        else
            print_error "Could not detect package manager. Please install manually: ${packages_to_install[*]}"
            exit 1
        fi
        
        print_info "Dependencies installed ✓"
    else
        print_info "All dependencies satisfied ✓"
    fi
}

###############################################################################
# Create Configuration
###############################################################################

create_config() {
    print_info "Setting up configuration..."
    
    # Create config directory
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    print_info "Created config directory: $CONFIG_DIR"
    
    # Copy config template if .env doesn't exist
    if [[ -f "$CONFIG_DIR/.env" ]]; then
        print_warn "Configuration file already exists at $CONFIG_DIR/.env"
        echo -n "Do you want to reconfigure? (yes/no): "
        read -r reconfigure
        if [[ "$reconfigure" != "yes" ]]; then
            print_info "Keeping existing configuration"
            return
        fi
    fi
    
    # Copy template
    cp .env.example "$CONFIG_DIR/.env"
    chmod 600 "$CONFIG_DIR/.env"
    
    # Update mailcow path in config
    sed -i "s|MAILCOW_PATH=.*|MAILCOW_PATH=$DETECTED_MAILCOW_PATH|" "$CONFIG_DIR/.env"
    
    print_info "Configuration template created at: $CONFIG_DIR/.env"
    echo ""
    print_warn "You MUST configure the following settings:"
    echo "  - HETZNER_HOST (your storage box hostname)"
    echo "  - HETZNER_USER (your storage box username)"
    echo "  - SSH_KEY_PATH (path to your SSH private key)"
    echo "  - HETZNER_REMOTE_PATH (remote backup directory)"
    echo ""
    
    # Open editor
    echo -n "Open configuration file in editor now? (yes/no): "
    read -r edit_config
    if [[ "$edit_config" == "yes" ]]; then
        ${EDITOR:-nano} "$CONFIG_DIR/.env"
    else
        print_warn "Remember to edit $CONFIG_DIR/.env before running backups!"
    fi
    
    # Validate required fields
    print_info "Validating configuration..."
    # shellcheck source=/dev/null
    source "$CONFIG_DIR/.env"
    
    local required_vars=("HETZNER_HOST" "HETZNER_USER" "SSH_KEY_PATH" "HETZNER_REMOTE_PATH")
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]] || [[ "${!var:-}" == *"your-"* ]]; then
            missing_vars+=("$var")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        print_error "The following required variables are not configured:"
        for var in "${missing_vars[@]}"; do
            echo "  - $var"
        done
        print_error "Please edit $CONFIG_DIR/.env and configure these variables"
        exit 1
    fi
    
    print_info "Configuration validated ✓"
}

###############################################################################
# Install Scripts
###############################################################################

install_scripts() {
    print_info "Installing backup scripts..."
    
    # Install backup script
    install -m 755 backup-to-hetzner.sh "$INSTALL_DIR/backup-to-hetzner.sh"
    print_info "Installed: $INSTALL_DIR/backup-to-hetzner.sh"
    
    # Install restore script
    install -m 755 restore-from-hetzner.sh "$INSTALL_DIR/restore-from-hetzner.sh"
    print_info "Installed: $INSTALL_DIR/restore-from-hetzner.sh"
    
    print_info "Scripts installed ✓"
}

###############################################################################
# Install Systemd Units
###############################################################################

install_systemd_units() {
    print_info "Installing systemd units..."
    
    # Install service
    cp systemd/mailcow-backup.service "$SYSTEMD_DIR/mailcow-backup.service"
    chmod 644 "$SYSTEMD_DIR/mailcow-backup.service"
    print_info "Installed: $SYSTEMD_DIR/mailcow-backup.service"
    
    # Install timer
    cp systemd/mailcow-backup.timer "$SYSTEMD_DIR/mailcow-backup.timer"
    chmod 644 "$SYSTEMD_DIR/mailcow-backup.timer"
    print_info "Installed: $SYSTEMD_DIR/mailcow-backup.timer"
    
    # Reload systemd
    systemctl daemon-reload
    print_info "Systemd units installed ✓"
}

###############################################################################
# Verify SSH Setup
###############################################################################

verify_ssh() {
    print_info "Verifying SSH configuration..."
    
    # shellcheck source=/dev/null
    source "$CONFIG_DIR/.env"
    
    # Check if SSH key exists
    if [[ ! -f "$SSH_KEY_PATH" ]]; then
        print_error "SSH key not found: $SSH_KEY_PATH"
        print_error "Please generate an SSH key pair and add the public key to your Hetzner storage box"
        print_error "Example: ssh-keygen -t rsa -b 4096 -f $SSH_KEY_PATH"
        exit 1
    fi
    
    # Check SSH key permissions
    local key_perms=$(stat -c %a "$SSH_KEY_PATH")
    if [[ "$key_perms" != "600" ]] && [[ "$key_perms" != "400" ]]; then
        print_warn "SSH key has insecure permissions: $key_perms"
        print_info "Fixing SSH key permissions..."
        chmod 600 "$SSH_KEY_PATH"
    fi
    print_info "SSH key found with correct permissions ✓"
    
    # Test connection
    print_info "Testing SSH connection to Hetzner storage box..."
    if ssh -i "$SSH_KEY_PATH" \
           -o BatchMode=yes \
           -o ConnectTimeout=10 \
           -o StrictHostKeyChecking=no \
           -p "$HETZNER_PORT" \
           "${HETZNER_USER}@${HETZNER_HOST}" \
           "exit" 2>/dev/null; then
        print_info "SSH connection successful ✓"
    else
        print_error "SSH connection failed!"
        print_error "Please verify:"
        print_error "  1. Your SSH public key is added to the Hetzner storage box"
        print_error "  2. The hostname and username are correct"
        print_error "  3. The storage box is accessible from this server"
        print_error ""
        print_error "To add your SSH key to Hetzner storage box:"
        print_error "  cat ${SSH_KEY_PATH}.pub"
        print_error "Then add this key in the Hetzner Robot panel"
        exit 1
    fi
    
    # Create remote directory
    print_info "Creating remote backup directory..."
    if ssh -i "$SSH_KEY_PATH" \
           -p "$HETZNER_PORT" \
           "${HETZNER_USER}@${HETZNER_HOST}" \
           "mkdir -p ${HETZNER_REMOTE_PATH}" 2>/dev/null; then
        print_info "Remote directory ready ✓"
    else
        print_warn "Could not create remote directory (may already exist)"
    fi
}

###############################################################################
# Enable Timer
###############################################################################

enable_timer() {
    print_info "Enabling and starting backup timer..."
    
    # Enable timer
    systemctl enable mailcow-backup.timer
    
    # Start timer
    systemctl start mailcow-backup.timer
    
    print_info "Timer enabled and started ✓"
    echo ""
    
    # Show timer status
    print_header "Timer Status"
    systemctl status mailcow-backup.timer --no-pager || true
    echo ""
    
    # Show next scheduled run
    print_info "Next scheduled backup:"
    systemctl list-timers mailcow-backup.timer --no-pager
}

###############################################################################
# Test Backup
###############################################################################

run_test_backup() {
    echo ""
    print_header "Test Backup"
    echo ""
    print_info "It's recommended to run a test backup now to verify the setup."
    echo -n "Run test backup now? (yes/no): "
    read -r run_test
    
    if [[ "$run_test" == "yes" ]]; then
        print_info "Starting test backup..."
        echo ""
        
        if "$INSTALL_DIR/backup-to-hetzner.sh"; then
            echo ""
            print_info "Test backup completed successfully! ✓"
            echo ""
            print_info "Check the log for details:"
            echo "  tail -f /var/log/mailcow-backup.log"
        else
            echo ""
            print_error "Test backup failed!"
            print_error "Check the log for details:"
            echo "  tail -f /var/log/mailcow-backup.log"
            exit 1
        fi
    else
        print_info "Skipping test backup"
        print_warn "You can run a manual backup later with:"
        echo "  sudo $INSTALL_DIR/backup-to-hetzner.sh"
    fi
}

###############################################################################
# Installation Summary
###############################################################################

print_summary() {
    echo ""
    print_header "Installation Complete!"
    echo ""
    print_info "The mailcow backup system has been installed successfully."
    echo ""
    echo "Configuration:"
    echo "  - Config file: $CONFIG_DIR/.env"
    echo "  - Backup script: $INSTALL_DIR/backup-to-hetzner.sh"
    echo "  - Restore script: $INSTALL_DIR/restore-from-hetzner.sh"
    echo "  - Systemd service: $SYSTEMD_DIR/mailcow-backup.service"
    echo "  - Systemd timer: $SYSTEMD_DIR/mailcow-backup.timer"
    echo ""
    echo "Usage:"
    echo "  - Manual backup: sudo $INSTALL_DIR/backup-to-hetzner.sh"
    echo "  - Restore backup: sudo $INSTALL_DIR/restore-from-hetzner.sh"
    echo "  - View logs: tail -f /var/log/mailcow-backup.log"
    echo "  - Check timer: systemctl status mailcow-backup.timer"
    echo "  - Next run: systemctl list-timers mailcow-backup.timer"
    echo ""
    echo "Timer management:"
    echo "  - Stop timer: systemctl stop mailcow-backup.timer"
    echo "  - Start timer: systemctl start mailcow-backup.timer"
    echo "  - Disable timer: systemctl disable mailcow-backup.timer"
    echo ""
    print_info "Happy backing up! 🚀"
}

###############################################################################
# Main Installation
###############################################################################

main() {
    print_header "Mailcow Backup to Hetzner - Installation"
    echo ""
    
    # Check prerequisites
    check_root
    check_mailcow
    check_docker
    install_dependencies
    
    echo ""
    
    # Create configuration
    create_config
    
    echo ""
    
    # Install components
    install_scripts
    install_systemd_units
    
    echo ""
    
    # Verify SSH setup
    verify_ssh
    
    echo ""
    
    # Enable timer
    enable_timer
    
    # Run test backup
    run_test_backup
    
    # Print summary
    print_summary
}

# Run installation
main "$@"
