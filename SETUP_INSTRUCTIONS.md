# SFTP Setup Instructions

## Architecture Overview

For the bind mount approach to work, **SFTP and Backend MUST run on the SAME server**.

- Backend and SFTP run on the same host
- CUCM connects to this server's IP for file uploads

## Setup Steps

### 1. Run install-sftp.sh

```bash
cd <project-directory>
sudo bash scripts/install-sftp.sh
```

When prompted, set a strong password for the `cucm-collector` SFTP user.

This will create:
- `/sftp/cucm-collector/` - chroot directory (owned by root)
- `/sftp/cucm-collector/received/` - upload directory (owned by cucm-collector)

### 2. Create the bind mount

After install-sftp.sh completes, run:

```bash
sudo mount --bind <project-directory>/storage/received /sftp/cucm-collector/received
```

Verify the mount:
```bash
mount | grep received
# Should show: <project-directory>/storage/received on /sftp/cucm-collector/received type none (rw,bind)
```

### 3. Make mount permanent

Add to `/etc/fstab`:
```bash
echo '<project-directory>/storage/received /sftp/cucm-collector/received none bind 0 0' | sudo tee -a /etc/fstab
```

### 4. Update .env with SFTP password

Edit `.env` and set:
```bash
SFTP_PASSWORD=<the password you set in step 1>
```

The .env file should have:
```bash
SFTP_HOST=localhost  # SFTP runs on same server
SFTP_REMOTE_BASE_DIR=  # Empty - backend creates job dirs directly
```

### 5. Test SFTP connection

```bash
# Test from backend's perspective
sftp cucm-collector@localhost
# Enter the password you set
# Try: ls, mkdir test, rmdir test, exit
```

### 6. Restart backend

```bash
# If running in background:
pkill -f uvicorn
./start.sh

# Or however you start the backend
```

### 7. Configure CUCM

In CUCM's SFTP settings for log collection:
- **SFTP Server IP**: Your server's IP address
- **Port**: `22`
- **Username**: `cucm-collector`
- **Password**: (the password you set)
- **Directory**: Let backend create it (don't specify)

## Verification

After setup, when a job runs:

1. Backend pre-creates: `{job-id}/{node}/` via SFTP to localhost
2. CUCM uploads to: `sftp://cucm-collector@<server-ip>/{job-id}/{node}/`
3. Files land in: `/sftp/cucm-collector/received/{job-id}/{node}/`
4. Via bind mount, files appear in: `<project-directory>/storage/received/{job-id}/{node}/`
5. Backend finds files immediately in `storage/received/`

## Troubleshooting

### Permission denied during install
```bash
sudo bash scripts/install-sftp.sh
```

### Check SFTP service
```bash
sudo systemctl status ssh
sudo tail -50 /var/log/auth.log
```

### Check directory ownership
```bash
ls -la /sftp/
ls -la /sftp/cucm-collector/
ls -la <project-directory>/storage/
```

### Test directory creation
```bash
sftp cucm-collector@localhost
mkdir test-job/test-node
ls
rmdir test-node
rmdir test-job
exit
```
