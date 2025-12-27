#!/usr/bin/env bash
set -euo pipefail

# === SFTP for CUCM Log Collector - Option B (Bind Mount) ===
# Chroots to /sftp/cucm-collector (safe, no user home ownership issues)
# Use bind mount to map to backend's storage/received

SFTP_USER="${SFTP_USER:-cucm-collector}"
SFTP_GROUP="${SFTP_GROUP:-$SFTP_USER}"
SFTP_CHROOT_BASE="${SFTP_CHROOT_BASE:-/sftp}"
SFTP_SUBDIR="${SFTP_SUBDIR:-received}"

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

echo "[5/7] Creating chroot structure..."
CHROOT_DIR="${SFTP_CHROOT_BASE}/${SFTP_USER}"
UPLOAD_DIR="${CHROOT_DIR}/${SFTP_SUBDIR}"

mkdir -p "$CHROOT_DIR"
mkdir -p "$UPLOAD_DIR"

# Chroot must be owned by root and not writable by the user
chown root:root "$CHROOT_DIR"
chmod 755 "$CHROOT_DIR"

# Upload dir owned by SFTP user
chown "${SFTP_USER}:${SFTP_GROUP}" "$UPLOAD_DIR"
chmod 775 "$UPLOAD_DIR"

echo "[6/7] Writing SSHD drop-in config: $CONF_FILE"
mkdir -p /etc/ssh/sshd_config.d

cat > "$CONF_FILE" <<EOF
# Auto-generated SFTP config for ${SFTP_USER} - Option B (bind mount)
# Enables legacy ssh-rsa hostkey algorithm for older clients (e.g., CUCM)
HostKeyAlgorithms +ssh-rsa
PubkeyAcceptedAlgorithms +ssh-rsa

# Force chrooted SFTP for this user
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
echo "======================================================================"
echo "DONE - SFTP Setup (Option B: Bind Mount)"
echo "======================================================================"
echo "SFTP user:        ${SFTP_USER}"
echo "Chroot directory: ${CHROOT_DIR}"
echo "Upload directory: ${UPLOAD_DIR}"
echo
echo "NEXT STEPS - Set up bind mount to backend storage:"
echo
echo "1. Create bind mount (run on THIS server):"
echo "   sudo mount --bind /path/to/backend/storage/received ${UPLOAD_DIR}"
echo
echo "   Example:"
echo "   sudo mount --bind /home/hadmin/cisco/storage/received ${UPLOAD_DIR}"
echo
echo "2. Make mount permanent (add to /etc/fstab):"
echo "   echo '/home/hadmin/cisco/storage/received ${UPLOAD_DIR} none bind 0 0' | sudo tee -a /etc/fstab"
echo
echo "3. Update backend config (.env):"
echo "   SFTP_REMOTE_BASE_DIR=${SFTP_SUBDIR}"
echo
echo "4. Restart backend"
echo
echo "Files will then land at:"
echo "  - CUCM uploads to:  ${SFTP_SUBDIR}/{job-id}/{node}/"
echo "  - Files appear at:  ${UPLOAD_DIR}/{job-id}/{node}/"
echo "  - Backend finds at: storage/received/{job-id}/{node}/ (via bind mount)"
echo "======================================================================"
