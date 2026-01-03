#!/usr/bin/env bash
set -euo pipefail

# === SFTP + SCP Server for CUCM/CSR Log Collector ===
# Supports both SFTP (for CUCM) and SCP (for IOS-XE/CSR1000v)
# Uses ChrootDirectory for security
#
# Key difference from install-sftp.sh:
#   - Does NOT use ForceCommand internal-sftp (which blocks SCP)
#   - Allows SCP protocol for IOS-XE packet capture export
#   - Still chroots user for security

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

echo "==============================================================="
echo "SFTP + SCP Server Installation"
echo "Supports: CUCM (SFTP) and CSR1000v/IOS-XE (SCP)"
echo "==============================================================="
echo

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
  # Use /bin/bash - ChrootDirectory provides security
  useradd -m -g "$SFTP_GROUP" -s /bin/bash "$SFTP_USER"
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

# For SCP to work inside chroot, we need some binaries and libraries
echo "[6/7] Setting up chroot environment for SCP..."

# Create necessary directories
mkdir -p "${CHROOT_DIR}/bin"
mkdir -p "${CHROOT_DIR}/lib"
mkdir -p "${CHROOT_DIR}/lib/x86_64-linux-gnu"
mkdir -p "${CHROOT_DIR}/lib64"
mkdir -p "${CHROOT_DIR}/usr/bin"
mkdir -p "${CHROOT_DIR}/usr/lib/x86_64-linux-gnu"
mkdir -p "${CHROOT_DIR}/usr/lib/openssh"
mkdir -p "${CHROOT_DIR}/dev"
mkdir -p "${CHROOT_DIR}/etc"

# Copy essential binaries
for bin in /bin/sh /bin/bash /usr/bin/scp; do
  if [[ -f "$bin" ]]; then
    dest="${CHROOT_DIR}${bin}"
    mkdir -p "$(dirname "$dest")"
    cp "$bin" "$dest" 2>/dev/null || true
  fi
done

# Copy sftp-server for SFTP subsystem
if [[ -f /usr/lib/openssh/sftp-server ]]; then
  cp /usr/lib/openssh/sftp-server "${CHROOT_DIR}/usr/lib/openssh/" 2>/dev/null || true
fi

# Create device nodes
mknod -m 666 "${CHROOT_DIR}/dev/null" c 1 3 2>/dev/null || true
mknod -m 666 "${CHROOT_DIR}/dev/zero" c 1 5 2>/dev/null || true
mknod -m 666 "${CHROOT_DIR}/dev/tty" c 5 0 2>/dev/null || true
mknod -m 666 "${CHROOT_DIR}/dev/urandom" c 1 9 2>/dev/null || true

# Copy required libraries for each binary
for binary in /bin/sh /bin/bash /usr/bin/scp /usr/lib/openssh/sftp-server; do
  if [[ -f "$binary" ]]; then
    for lib in $(ldd "$binary" 2>/dev/null | grep -oE '/[^ ]+' | sort -u); do
      if [[ -f "$lib" ]]; then
        dest="${CHROOT_DIR}${lib}"
        mkdir -p "$(dirname "$dest")"
        cp "$lib" "$dest" 2>/dev/null || true
      fi
    done
  fi
done

# Copy the dynamic linker
for ld in /lib64/ld-linux-x86-64.so.2 /lib/ld-linux.so.2 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2; do
  if [[ -f "$ld" ]]; then
    dest="${CHROOT_DIR}${ld}"
    mkdir -p "$(dirname "$dest")"
    cp "$ld" "$dest" 2>/dev/null || true
  fi
done

# Create minimal /etc files
echo "root:x:0:0:root:/root:/bin/bash" > "${CHROOT_DIR}/etc/passwd"
echo "${SFTP_USER}:x:$(id -u "$SFTP_USER"):$(id -g "$SFTP_USER")::/:/bin/bash" >> "${CHROOT_DIR}/etc/passwd"
echo "root:x:0:" > "${CHROOT_DIR}/etc/group"
echo "${SFTP_GROUP}:x:$(id -g "$SFTP_USER"):" >> "${CHROOT_DIR}/etc/group"

# Copy name service libraries for user lookup
for lib in /lib/x86_64-linux-gnu/libnss_* /usr/lib/x86_64-linux-gnu/libnss_*; do
  if [[ -f "$lib" ]]; then
    dest="${CHROOT_DIR}${lib}"
    mkdir -p "$(dirname "$dest")"
    cp "$lib" "$dest" 2>/dev/null || true
  fi
done

echo "[7/7] Writing SSHD drop-in config: $CONF_FILE"
mkdir -p /etc/ssh/sshd_config.d

cat > "$CONF_FILE" <<EOF
# Auto-generated config for ${SFTP_USER} - SFTP + SCP support
# Enables legacy ssh-rsa hostkey algorithm for older clients (e.g., CUCM, IOS-XE)
HostKeyAlgorithms +ssh-rsa
PubkeyAcceptedAlgorithms +ssh-rsa

# Chroot user to restricted directory
# Note: ForceCommand is NOT used, allowing both SFTP and SCP
Match User ${SFTP_USER}
  ChrootDirectory ${CHROOT_DIR}
  X11Forwarding no
  AllowTcpForwarding no
  PasswordAuthentication yes
EOF

echo "[8/8] Validating sshd config and restarting SSH..."
/usr/sbin/sshd -t

# Ubuntu/Debian uses "ssh"; some distros use "sshd"
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

systemctl --no-pager --full status ssh 2>/dev/null || systemctl --no-pager --full status sshd 2>/dev/null || true

echo
echo "========================================================================"
echo "DONE - SFTP + SCP Setup (Chroot with SCP support)"
echo "========================================================================"
echo "SFTP/SCP user:    ${SFTP_USER}"
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
echo "SUPPORTED PROTOCOLS:"
echo "  - SFTP: CUCM 'file get activelog' uses SFTP subsystem"
echo "  - SCP:  IOS-XE 'monitor capture export scp://...' uses SCP"
echo
echo "Files will land at:"
echo "  - Uploads to:     /${SFTP_SUBDIR}/{capture-id}/filename"
echo "  - Files appear:   ${UPLOAD_DIR}/{capture-id}/filename"
echo "  - Backend finds:  storage/received/{capture-id}/filename (via bind mount)"
echo "========================================================================"
