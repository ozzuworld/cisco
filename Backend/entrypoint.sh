#!/bin/bash
# ==============================================================================
# CUCM Log Collector - Container Entrypoint
# ==============================================================================
# 1. Sets up the SFTP user password from environment variables
# 2. Generates SSH host keys if they don't exist
# 3. Starts OpenSSH sshd for SFTP (if enabled)
# 4. Runs uvicorn (FastAPI) as the main process
# ==============================================================================

set -e

# --- SFTP Server Setup ---
if [ "${SFTP_SERVER_ENABLED}" = "true" ] || [ "${SFTP_SERVER_ENABLED}" = "True" ] || [ "${SFTP_SERVER_ENABLED}" = "1" ]; then
    echo "[entrypoint] Setting up OpenSSH SFTP server..."

    # Set the SFTP user password from environment variable
    SFTP_USER="${SFTP_USERNAME:-cucm-collector}"
    SFTP_PASS="${SFTP_PASSWORD:-}"

    if [ -z "$SFTP_PASS" ]; then
        echo "[entrypoint] WARNING: SFTP_PASSWORD not set - SFTP authentication will fail!"
    else
        echo "${SFTP_USER}:${SFTP_PASS}" | chpasswd
        echo "[entrypoint] SFTP user '${SFTP_USER}' password configured"
    fi

    # Ensure the SFTP chroot directory exists with correct ownership
    # ChrootDirectory requires: owned by root, no group/other write (755)
    # CUCM uploads land in per-capture subdirectories created by the app
    SFTP_HOME="/app/storage/received"
    mkdir -p "${SFTP_HOME}"
    chown root:root "${SFTP_HOME}"
    chmod 755 "${SFTP_HOME}"

    # Generate SSH host keys if they don't exist
    KEY_DIR="/app/storage"
    if [ ! -f "${KEY_DIR}/ssh_host_ed25519_key" ]; then
        echo "[entrypoint] Generating Ed25519 host key..."
        ssh-keygen -t ed25519 -f "${KEY_DIR}/ssh_host_ed25519_key" -N "" -q
    fi
    if [ ! -f "${KEY_DIR}/ssh_host_ecdsa_key" ]; then
        echo "[entrypoint] Generating ECDSA host key..."
        ssh-keygen -t ecdsa -b 256 -f "${KEY_DIR}/ssh_host_ecdsa_key" -N "" -q
    fi
    if [ ! -f "${KEY_DIR}/ssh_host_rsa_key" ]; then
        echo "[entrypoint] Generating RSA host key..."
        ssh-keygen -t rsa -b 2048 -f "${KEY_DIR}/ssh_host_rsa_key" -N "" -q
    fi

    # Fix host key permissions
    chmod 600 "${KEY_DIR}"/ssh_host_*_key 2>/dev/null || true
    chmod 644 "${KEY_DIR}"/ssh_host_*_key.pub 2>/dev/null || true

    # Create required directory for sshd privilege separation
    mkdir -p /run/sshd

    # Ensure /etc/ssh/moduli exists (required for DH group exchange algorithms)
    # Some slim Docker images may not include it. Without it, sshd silently
    # drops connections during key exchange ("Connection closed [preauth]").
    if [ ! -s /etc/ssh/moduli ]; then
        echo "[entrypoint] WARNING: /etc/ssh/moduli is missing or empty."
        echo "[entrypoint] DH group exchange algorithms will not work."
        echo "[entrypoint] This is handled by sshd_config excluding group-exchange algorithms."
    fi

    # Validate sshd config
    if /usr/sbin/sshd -t -f /app/sshd_config_sftp; then
        echo "[entrypoint] sshd config valid, starting SFTP server on port ${SFTP_SERVER_PORT:-2222}..."
        # Use -D (no daemonize) + -e (log to stderr) so logs appear in Docker output
        # Run in background with & so the entrypoint can continue to start uvicorn
        /usr/sbin/sshd -D -e -f /app/sshd_config_sftp &
        SSHD_PID=$!
        echo "$SSHD_PID" > /tmp/sshd_sftp.pid
        echo "[entrypoint] OpenSSH SFTP server started (PID: ${SSHD_PID})"
        echo "[entrypoint] SFTP listening on port ${SFTP_SERVER_PORT:-2222}"
        echo "[entrypoint] NOTE: If running on Docker Desktop (Windows/Mac), ensure"
        echo "[entrypoint]   Windows Firewall allows inbound TCP port ${SFTP_SERVER_PORT:-2222}"
        echo "[entrypoint]   PowerShell: New-NetFirewallRule -DisplayName 'CUCM SFTP' -Direction Inbound -Protocol TCP -LocalPort ${SFTP_SERVER_PORT:-2222} -Action Allow"
    else
        echo "[entrypoint] ERROR: Invalid sshd config! SFTP server will NOT start."
    fi
else
    echo "[entrypoint] SFTP server disabled (SFTP_SERVER_ENABLED != true)"
fi

# --- Run the main application ---
echo "[entrypoint] Starting uvicorn (FastAPI)..."
exec python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
