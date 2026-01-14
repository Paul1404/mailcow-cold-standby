# Mailcow Cold Standby Backup

Automated backup solution for [mailcow-dockerized](https://mailcow.email/) to Hetzner storage boxes using rsync over SSH.

## Features

- **Secure SSH key authentication** - No passwords stored
- **Multithreaded backups** - Configurable CPU threads for faster backups
- **Intelligent disk space checks** - Pre-flight validation before backup
- **Lock file protection** - Prevents overlapping backups with stale lock detection
- **SHA-256 integrity verification** - Checksum validation after transfer
- **Automated retention policy** - Configurable cleanup of old backups (local and remote)
- **Systemd timer integration** - Daily scheduled backups at 3 AM
- **Email notifications** - Optional success/failure notifications using mailcow's mail system
- **Comprehensive logging** - Detailed logs with timestamps and levels
- **Full restore capability** - Interactive restore script with integrity checks

## Prerequisites

- **Operating System**: Rocky Linux 10 (or compatible RHEL-based distribution)
- **Mailcow**: mailcow-dockerized installed and running
- **Hetzner Storage Box**: Active Hetzner storage box with SSH access
- **SSH Key Pair**: Generated SSH key pair for authentication
- **Root Access**: Installation requires root or sudo privileges
- **Dependencies**: rsync, sha256sum (included by default in coreutils)

## Installation

1. Clone this repository:

```bash
cd /opt
git clone https://github.com/Paul1404/mailcow-cold-standby.git
cd mailcow-cold-standby
```

2. Run the installation script:

```bash
sudo ./install.sh
```

The installation script will:
- Auto-detect your mailcow installation
- Install required dependencies (rsync if missing)
- Create configuration directory at `/etc/mailcow-backup/`
- Copy scripts to `/usr/local/bin/`
- Install systemd service and timer units
- Validate SSH key authentication
- Enable and start the backup timer
- Optionally run a test backup

3. Configure your settings:

Edit `/etc/mailcow-backup/.env` with your Hetzner storage box credentials:

```bash
sudo nano /etc/mailcow-backup/.env
```

## Configuration

All configuration is stored in `/etc/mailcow-backup/.env`. Key parameters:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `HETZNER_HOST` | Storage box hostname (e.g., u123456.your-storagebox.de) | Required |
| `HETZNER_PORT` | SSH port for Hetzner storage box | `23` |
| `HETZNER_USER` | Storage box username | Required |
| `SSH_KEY_PATH` | Path to SSH private key | `/root/.ssh/id_rsa_hetzner` |
| `HETZNER_REMOTE_PATH` | Remote directory for backups | Required |
| `MAILCOW_PATH` | Path to mailcow installation | `/opt/mailcow-dockerized` |
| `BACKUP_COMPONENTS` | Components to backup (all, or specific) | `all` |
| `THREADS` | Number of CPU threads for backup | `4` |
| `LOCAL_RETENTION_DAYS` | Days to keep local backups | `7` |
| `REMOTE_RETENTION_DAYS` | Days to keep remote backups | `30` |
| `LOCK_TIMEOUT_HOURS` | Hours before lock is considered stale | `24` |
| `LOG_FILE` | Path to log file | `/var/log/mailcow-backup.log` |
| `TEMP_BACKUP_DIR` | Temporary directory for backups | `/tmp/mailcow-backup` |
| `EMAIL_NOTIFICATIONS` | Enable email notifications (true/false) | `false` |
| `NOTIFICATION_EMAIL` | Email address for notifications | Required if enabled |
| `NOTIFICATION_FROM` | From address for notifications | `mailcow-backup@example.com` |

### Component Options

You can backup specific components instead of `all`:
- `vmail` - Email data
- `crypt` - Encrypted data
- `redis` - Redis database
- `rspamd` - Rspamd data
- `postfix` - Postfix configuration
- `mysql` - MySQL/MariaDB databases

Example for selective backup:
```bash
BACKUP_COMPONENTS="mysql crypt redis"
```

## Usage

### Manual Backup

Run a backup manually at any time:

```bash
sudo /usr/local/bin/backup-to-hetzner.sh
```

### Restore from Backup

Restore from a Hetzner backup interactively:

```bash
sudo /usr/local/bin/restore-from-hetzner.sh
```

The restore script will:
1. List available backups from Hetzner
2. Let you select which backup to restore
3. Verify you want to proceed (destructive operation)
4. Check disk space requirements
5. Download the selected backup
6. Verify integrity with checksums
7. Stop mailcow containers
8. Restore the backup
9. Start mailcow containers

### Systemd Timer Management

Check timer status and next scheduled run:

```bash
systemctl status mailcow-backup.timer
systemctl list-timers mailcow-backup.timer
```

Stop the timer:

```bash
sudo systemctl stop mailcow-backup.timer
```

Start the timer:

```bash
sudo systemctl start mailcow-backup.timer
```

Disable automatic backups:

```bash
sudo systemctl disable mailcow-backup.timer
```

Enable automatic backups:

```bash
sudo systemctl enable mailcow-backup.timer
```

Change backup schedule (edit timer unit):

```bash
sudo systemctl edit mailcow-backup.timer
```

### View Logs

View backup logs in real-time:

```bash
tail -f /var/log/mailcow-backup.log
```

View systemd journal logs:

```bash
journalctl -u mailcow-backup.service -f
```

View recent backup operations:

```bash
journalctl -u mailcow-backup.service --since today
```

### Email Notifications

Enable email notifications to receive alerts about backup success or failure:

1. Edit configuration:

```bash
sudo nano /etc/mailcow-backup/.env
```

2. Set notification parameters:

```bash
EMAIL_NOTIFICATIONS=true
NOTIFICATION_EMAIL=admin@yourdomain.com
NOTIFICATION_FROM=mailcow-backup@yourdomain.com
```

3. The script connects directly to mailcow's SMTP service on `localhost:25` (no MTA installation needed on host).

4. Requirements: `netcat` (nmap-ncat) is recommended for SMTP communication:

```bash
sudo dnf install -y nmap-ncat
```

5. Notifications include:
   - Backup success with size and location details
   - Backup failure with error information and log file path
   - Hostname and timestamp for identification

## Hetzner Storage Box Setup

1. **Generate SSH Key Pair** (if you don't have one):

```bash
ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa_hetzner
```

2. **Add Public Key to Hetzner Storage Box**:

Display your public key:

```bash
cat /root/.ssh/id_rsa_hetzner.pub
```

Add this key in the Hetzner Robot panel:
- Log in to https://robot.hetzner.com/
- Go to your storage box settings
- Navigate to "SSH Support" or "Access"
- Add your public key

**Note**: Hetzner Storage Boxes use a restricted shell environment that starts in the `/home` directory. You don't have access to directories outside `/home`, so use relative paths (e.g., `mailcow-backups`) or absolute paths within `/home` (e.g., `/home/mailcow-backups`) for your backup destination.

3. **Test SSH Connection**:

```bash
ssh -i /root/.ssh/id_rsa_hetzner -p 23 u123456@u123456.your-storagebox.de
```

## Troubleshooting

### SSH Authentication Fails

**Problem**: "SSH connection failed" error during backup or installation.

**Solutions**:
1. Verify your SSH public key is added to Hetzner storage box
2. Check SSH key permissions: `chmod 600 /root/.ssh/id_rsa_hetzner`
3. Test connection manually: `ssh -i /root/.ssh/id_rsa_hetzner -p 23 user@host`
4. Ensure `BatchMode=yes` works (no password prompts)

### Insufficient Disk Space

**Problem**: "Insufficient disk space" error before backup starts.

**Solutions**:
1. Free up space on the filesystem containing `/tmp`
2. Change `TEMP_BACKUP_DIR` to a filesystem with more space
3. Clean up old local backups manually
4. Reduce `LOCAL_RETENTION_DAYS` to clean up backups more aggressively

### Stale Lock File

**Problem**: "Backup is already running" but no process exists.

**Solutions**:
1. Wait for `LOCK_TIMEOUT_HOURS` (default 24h) for automatic override
2. Manually remove lock: `sudo rm /var/lock/mailcow-backup.lock`
3. Check for zombie processes: `ps aux | grep backup-to-hetzner`

### Checksum Verification Failed

**Problem**: "Backup integrity check failed" after transfer.

**Solutions**:
1. Check network stability between server and Hetzner
2. Re-run the backup to transfer again
3. Verify rsync completed without errors in logs
4. Check available space on Hetzner storage box

### Mailcow Path Not Detected

**Problem**: Installation script can't find mailcow.

**Solutions**:
1. Ensure mailcow is installed at a standard location
2. Provide custom path when prompted
3. Verify `docker-compose.yml` and `helper-scripts/backup_and_restore.sh` exist
4. Manually set `MAILCOW_PATH` in `/etc/mailcow-backup/.env`

### Timer Not Running

**Problem**: Backups don't run automatically.

**Solutions**:
1. Check timer is enabled: `systemctl is-enabled mailcow-backup.timer`
2. Check timer is active: `systemctl is-active mailcow-backup.timer`
3. View timer status: `systemctl status mailcow-backup.timer`
4. Check for errors: `journalctl -u mailcow-backup.service`
5. Manually enable: `sudo systemctl enable --now mailcow-backup.timer`

## Security Best Practices

### SSH Key Security

- **Permissions**: Ensure SSH private key has `600` or `400` permissions
- **Storage**: Keep SSH keys in secure location (e.g., `/root/.ssh/`)
- **Backup**: Store a secure backup of your SSH private key offline
- **Passphrase**: Consider using a passphrase-protected key for additional security

### Configuration File Protection

- The configuration directory `/etc/mailcow-backup/` has `700` permissions (owner only)
- The `.env` file has `600` permissions (owner read/write only)
- Never commit `.env` files to version control (already in `.gitignore`)

### Hetzner Storage Box Security

- Enable SSH key authentication only (disable password authentication)
- Use sub-accounts with restricted permissions if possible
- Regularly rotate SSH keys
- Monitor access logs in Hetzner Robot panel

### Network Security

- Consider using a firewall to restrict outbound connections
- Use VPN or private network for added security
- Monitor network traffic for unusual patterns

## Architecture

### Backup Process Flow

1. **Pre-flight Checks**
   - Acquire lock file (prevent concurrent runs)
   - Load and validate configuration
   - Test SSH connection to Hetzner
   - Calculate required disk space (50% of mailcow volumes)
   - Verify sufficient space available

2. **Backup Execution**
   - Create temporary backup directory
   - Run mailcow's native `backup_and_restore.sh` script
   - Use multithreading for faster backup
   - Generate SHA-256 checksums for all files

3. **Transfer**
   - Sync backup directory to Hetzner via rsync over SSH
   - Use compression (`-z`) to reduce bandwidth
   - Archive mode (`-a`) preserves permissions and timestamps

4. **Verification**
   - Download remote checksums
   - Compare with local checksums
   - Fail backup if checksums don't match

5. **Cleanup**
   - Remove local backups older than `LOCAL_RETENTION_DAYS`
   - Remove remote backups older than `REMOTE_RETENTION_DAYS`
   - Release lock file

### File Structure

```
mailcow-cold-standby/
├── .env.example              # Configuration template
├── .gitignore               # Git ignore rules
├── backup-to-hetzner.sh     # Main backup script
├── restore-from-hetzner.sh  # Restore script
├── install.sh               # Installation script
├── LICENSE                  # MIT License
├── README.md                # This file
├── logrotate/
│   └── mailcow-backup       # Logrotate configuration
└── systemd/
    ├── mailcow-backup.service  # Systemd service unit
    └── mailcow-backup.timer    # Systemd timer unit
```

### System Integration

```
/etc/mailcow-backup/.env         # Configuration (created during install)
/usr/local/bin/backup-to-hetzner.sh
/usr/local/bin/restore-from-hetzner.sh
/etc/systemd/system/mailcow-backup.service
/etc/systemd/system/mailcow-backup.timer
/etc/logrotate.d/mailcow-backup  # Log rotation config
/var/log/mailcow-backup.log      # Main log file
/var/log/mailcow-restore.log     # Restore log file
/var/lock/mailcow-backup.lock    # Lock file (temporary)
```

## Performance Tuning

### Thread Count

Adjust `THREADS` based on your CPU:
- Recommended: `CPU cores - 2`
- Example: 8-core system → `THREADS=6`
- Don't set too high or mailcow services may become unresponsive

### Backup Schedule

Default schedule is 3:00 AM daily. To change:

```bash
sudo systemctl edit mailcow-backup.timer
```

Add override:

```ini
[Timer]
OnCalendar=*-*-* 02:00:00
RandomizedDelaySec=30min
```

### Retention Policy

Balance storage costs vs. recovery options:
- **Local**: Keep 7 days for quick recovery
- **Remote**: Keep 30 days for long-term retention
- Adjust based on your RPO (Recovery Point Objective)

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

For issues and questions:
- GitHub Issues: https://github.com/Paul1404/mailcow-cold-standby/issues
- Mailcow Docs: https://docs.mailcow.email/

## Acknowledgments

- [mailcow-dockerized](https://mailcow.email/) - The excellent mail server suite
- [Hetzner](https://www.hetzner.com/) - Reliable and affordable storage boxes