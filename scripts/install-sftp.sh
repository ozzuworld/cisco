#!/usr/bin/env bash
set -euo pipefail

# === SFTP for CUCM Log Collector - BE-017 ===
# Chroots SFTP user directly to backend's storage/received directory
# Files land at: storage/received/{job-id}/{node}/
# Backend finds artifacts immediately without additional transfer

SFTP_USER="${SFTP_USER:-cucm-collector}"
SFTP_GROUP="${SFTP_GROUP:-$SFTP_USER}"

# BE-017: Default to backend's storage/received directory
# This should be the ABSOLUTE path to your backend's storage/received directory
BACKEND_STORAGE="${BACKEND_STORAGE:-/home/hadmin/cisco/storage/received}"

SSH_PORT="${SSH_PORT:-22}"
CONF_FILE="/etc/ssh/sshd_config.d/99-sftp-${SFTP_USER}.conf"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

echo "[1/7] Installing OpenSSH server..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y openssh-server

echo "[2/7] Ensuring runtime dir exists..."
mkdir -p /run/sshd
chmod 755 /run/sshd

echo "[3/7] Creating group/user..."
if ! getent group "$SFTP_GROUP" >/dev/null; then
  groupadd "$SFTP_GROUP"
fi

if ! id "$SFTP_USER" >/dev/null 2>&1; then
  useradd -m -g "$SFTP_GROUP" -s /usr/sbin/nologin "$SFTP_USER"
fi

echo "[4/7] Setting password for $SFTP_USER..."
echo "Enter a NEW password for '$SFTP_USER':"
read -r -s PASS1
echo
echo "Confirm password:"
read -r -s PASS2
echo
if [[ "$PASS1" != "$PASS2" ]]; then
  echo "Passwords do not match. Aborting."
  exit 1
fi
echo "${SFTP_USER}:${PASS1}" | chpasswd
unset PASS1 PASS2

echo "[5/7] Configuring chroot to backend storage..."
# BE-017: Chroot directly to backend's storage/received directory
CHROOT_DIR="$BACKEND_STORAGE"

# Create the chroot directory
mkdir -p "$CHROOT_DIR"

# Chroot must be owned by root for security
chown root:root "$CHROOT_DIR"
chmod 755 "$CHROOT_DIR"

# SFTP user must be able to write inside the chroot
# We'll set proper permissions on job subdirectories as they're created
echo "SFTP chroot will be: $CHROOT_DIR"
echo "Backend will create job subdirectories with proper permissions"

echo "[6/7] Writing SSHD drop-in config: $CONF_FILE"
mkdir -p /etc/ssh/sshd_config.d

cat > "$CONF_FILE" <<EOF
# Auto-generated SFTP config for ${SFTP_USER} - BE-017
# Enables legacy ssh-rsa hostkey algorithm for older clients (e.g., CUCM)
HostKeyAlgorithms +ssh-rsa
PubkeyAcceptedAlgorithms +ssh-rsa

# Force chrooted SFTP for this user - chroot to backend storage
Match User ${SFTP_USER}
  ChrootDirectory ${CHROOT_DIR}
  ForceCommand internal-sftp
  X11Forwarding no
  AllowTcpForwarding no
  PasswordAuthentication yes
EOF

echo "[7/7] Validating sshd config and restarting SSH..."
/usr/sbin/sshd -t

# Ubuntu/Debian uses "ssh"; some distros use "sshd"
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

systemctl --no-pager --full status ssh 2>/dev/null || systemctl --no-pager --full status sshd 2>/dev/null || true

echo
echo "DONE - BE-017 SFTP Setup"
echo "SFTP user:        ${SFTP_USER}"
echo "Chroot directory: ${CHROOT_DIR}"
echo
echo "IMPORTANT for backend configuration:"
echo " - SFTP_REMOTE_BASE_DIR should be empty or just '{job-id}/{node}'"
echo " - Backend creates: {job-id}/{node}/ with proper permissions"
echo " - CUCM uploads to: {job-id}/{node}/"
echo " - Files land at:   ${CHROOT_DIR}/{job-id}/{node}/"
echo " - Backend finds them at: storage/received/{job-id}/{node}/"
echo
echo "NOTE: Backend must run as root or same user that owns ${CHROOT_DIR}"
echo "      to create job subdirectories with proper permissions"
