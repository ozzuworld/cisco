"""
Embedded SFTP Server for CUCM Log Collector

This module provides an asyncssh-based SFTP server that runs inside the Docker
container, allowing CUCM devices to push log files directly to the application's
storage directory without requiring a separate system-level SFTP server.

Features:
- Runs alongside FastAPI in the same container
- Uses asyncssh (already a dependency) for the SFTP server
- Files are written directly to storage/received/
- Auto-generates SSH host keys on first run
- Configurable via environment variables
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Optional

import asyncssh
from asyncssh import SFTPServer, SFTPAttrs, SFTPName

logger = logging.getLogger(__name__)


class CUCMSFTPServer(SFTPServer):
    """
    Custom SFTP server implementation for receiving files from CUCM.

    This server restricts operations to a specific root directory (chroot-like)
    and only allows the operations CUCM needs: mkdir, put (write), stat.
    """

    def __init__(self, conn: asyncssh.SSHServerConnection, root_path: Path):
        """
        Initialize the SFTP server handler.

        Args:
            conn: The SSH connection
            root_path: Root directory for all SFTP operations (storage/received)
        """
        super().__init__(conn)
        self._root = root_path.resolve()
        self._conn = conn
        self._bytes_written = {}  # Track bytes per file handle
        logger.info(f"SFTP session started, root={self._root}")

    def _resolve_path(self, path: str) -> Path:
        """
        Resolve a client path to an absolute path within the root.

        Prevents path traversal attacks by ensuring the resolved path
        is always within the root directory.

        Args:
            path: Client-provided path (may be relative or absolute)

        Returns:
            Resolved absolute path within root
        """
        # Normalize the path - remove leading slashes, handle . and ..
        clean_path = path.lstrip('/')

        # Resolve relative to root
        resolved = (self._root / clean_path).resolve()

        # Security check: ensure path is within root
        try:
            resolved.relative_to(self._root)
        except ValueError:
            # Path escapes root - return root instead
            logger.warning(f"Path traversal attempt blocked: {path}")
            return self._root

        return resolved

    def _make_attrs(self, path: Path) -> SFTPAttrs:
        """Create SFTPAttrs from a filesystem path."""
        try:
            stat_result = path.stat()
            return SFTPAttrs(
                size=stat_result.st_size,
                uid=stat_result.st_uid,
                gid=stat_result.st_gid,
                permissions=stat_result.st_mode,
                atime=int(stat_result.st_atime),
                mtime=int(stat_result.st_mtime)
            )
        except OSError:
            return SFTPAttrs()

    async def stat(self, path: str) -> SFTPAttrs:
        """Get attributes of a file or directory."""
        resolved = self._resolve_path(path)
        logger.debug(f"SFTP stat: {path} -> {resolved}")

        if not resolved.exists():
            raise asyncssh.SFTPError(asyncssh.FX_NO_SUCH_FILE, f"No such file: {path}")

        return self._make_attrs(resolved)

    async def lstat(self, path: str) -> SFTPAttrs:
        """Get attributes without following symlinks."""
        # For simplicity, treat same as stat (no symlinks expected)
        return await self.stat(path)

    async def setstat(self, path: str, attrs: SFTPAttrs) -> None:
        """Set attributes on a file - limited support."""
        resolved = self._resolve_path(path)
        logger.debug(f"SFTP setstat: {path} -> {resolved}")

        if not resolved.exists():
            raise asyncssh.SFTPError(asyncssh.FX_NO_SUCH_FILE, f"No such file: {path}")

        # Only support chmod if permissions are provided
        if attrs.permissions is not None:
            try:
                resolved.chmod(attrs.permissions)
            except OSError as e:
                logger.warning(f"Failed to chmod {path}: {e}")

    async def opendir(self, path: str):
        """Open a directory for reading."""
        resolved = self._resolve_path(path)
        logger.debug(f"SFTP opendir: {path} -> {resolved}")

        if not resolved.exists():
            raise asyncssh.SFTPError(asyncssh.FX_NO_SUCH_FILE, f"No such directory: {path}")

        if not resolved.is_dir():
            raise asyncssh.SFTPError(asyncssh.FX_FAILURE, f"Not a directory: {path}")

        return resolved

    async def readdir(self, handle) -> list:
        """Read directory contents."""
        dir_path = handle  # handle is the Path from opendir
        logger.debug(f"SFTP readdir: {dir_path}")

        entries = []
        try:
            for entry in dir_path.iterdir():
                name = entry.name
                attrs = self._make_attrs(entry)
                entries.append(SFTPName(name.encode(), name, attrs))
        except OSError as e:
            logger.error(f"Error reading directory {dir_path}: {e}")

        return entries

    async def mkdir(self, path: str, attrs: SFTPAttrs) -> None:
        """Create a directory."""
        resolved = self._resolve_path(path)
        logger.info(f"SFTP mkdir: {path} -> {resolved}")

        try:
            # Create with parents (CUCM sometimes needs nested directories)
            resolved.mkdir(parents=True, exist_ok=True)

            # Set permissions if provided, otherwise use sensible default
            mode = attrs.permissions if attrs.permissions is not None else 0o775
            resolved.chmod(mode)

            logger.debug(f"Created directory: {resolved}")
        except OSError as e:
            logger.error(f"Failed to create directory {path}: {e}")
            raise asyncssh.SFTPError(asyncssh.FX_FAILURE, str(e))

    async def rmdir(self, path: str) -> None:
        """Remove a directory (empty only)."""
        resolved = self._resolve_path(path)
        logger.info(f"SFTP rmdir: {path} -> {resolved}")

        # Safety: don't allow removing root
        if resolved == self._root:
            raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, "Cannot remove root")

        try:
            resolved.rmdir()
        except OSError as e:
            logger.error(f"Failed to remove directory {path}: {e}")
            raise asyncssh.SFTPError(asyncssh.FX_FAILURE, str(e))

    async def open(self, path: str, pflags: int, attrs: SFTPAttrs):
        """Open a file for reading or writing."""
        resolved = self._resolve_path(path)
        logger.info(f"SFTP open: {path} -> {resolved} (flags={pflags})")

        # Determine mode from flags
        if pflags & asyncssh.FXF_WRITE:
            if pflags & asyncssh.FXF_APPEND:
                mode = 'ab'
            elif pflags & asyncssh.FXF_TRUNC or pflags & asyncssh.FXF_CREAT:
                mode = 'wb'
            else:
                mode = 'r+b'
        else:
            mode = 'rb'

        try:
            # Ensure parent directory exists for writes
            if 'w' in mode or 'a' in mode:
                resolved.parent.mkdir(parents=True, exist_ok=True)

            file_handle = open(resolved, mode)
            logger.debug(f"Opened file: {resolved} mode={mode}")
            return file_handle

        except OSError as e:
            logger.error(f"Failed to open file {path}: {e}")
            raise asyncssh.SFTPError(asyncssh.FX_FAILURE, str(e))

    async def read(self, handle, offset: int, length: int) -> bytes:
        """Read from an open file."""
        try:
            handle.seek(offset)
            data = handle.read(length)
            return data
        except OSError as e:
            logger.error(f"Failed to read from file: {e}")
            raise asyncssh.SFTPError(asyncssh.FX_FAILURE, str(e))

    async def write(self, handle, offset: int, data: bytes) -> int:
        """Write to an open file."""
        try:
            handle.seek(offset)
            handle.write(data)
            handle_id = id(handle)
            self._bytes_written[handle_id] = self._bytes_written.get(handle_id, 0) + len(data)
            return len(data)
        except OSError as e:
            logger.error(f"Failed to write to file: {e}")
            raise asyncssh.SFTPError(asyncssh.FX_FAILURE, str(e))

    async def close(self, handle) -> None:
        """Close an open file or directory handle."""
        if hasattr(handle, 'close'):
            try:
                handle_id = id(handle)
                name = getattr(handle, 'name', 'unknown')
                bytes_total = self._bytes_written.pop(handle_id, 0)
                handle.close()
                if bytes_total > 0:
                    logger.info(f"File write complete: {name} ({bytes_total} bytes)")
                else:
                    logger.debug(f"File handle closed: {name}")
            except Exception as e:
                logger.warning(f"Error closing handle: {e}")

    async def remove(self, path: str) -> None:
        """Remove a file."""
        resolved = self._resolve_path(path)
        logger.info(f"SFTP remove: {path} -> {resolved}")

        try:
            resolved.unlink()
        except OSError as e:
            logger.error(f"Failed to remove file {path}: {e}")
            raise asyncssh.SFTPError(asyncssh.FX_FAILURE, str(e))

    async def rename(self, oldpath: str, newpath: str) -> None:
        """Rename/move a file."""
        old_resolved = self._resolve_path(oldpath)
        new_resolved = self._resolve_path(newpath)
        logger.info(f"SFTP rename: {oldpath} -> {newpath}")

        try:
            old_resolved.rename(new_resolved)
        except OSError as e:
            logger.error(f"Failed to rename {oldpath} to {newpath}: {e}")
            raise asyncssh.SFTPError(asyncssh.FX_FAILURE, str(e))

    async def realpath(self, path: str) -> str:
        """Return canonical path."""
        resolved = self._resolve_path(path)
        # Return path relative to root (client's view)
        try:
            rel_path = resolved.relative_to(self._root)
            result = '/' + str(rel_path) if str(rel_path) != '.' else '/'
            logger.info(f"SFTP realpath: {path} -> {result}")
            return result
        except ValueError:
            logger.info(f"SFTP realpath: {path} -> /")
            return '/'

    def exit(self) -> None:
        """Called when SFTP session ends."""
        logger.debug("SFTP session ended")


class CUCMSSHServer(asyncssh.SSHServer):
    """
    SSH server that handles authentication and spawns SFTP sessions.
    """

    def __init__(self, root_path: Path, username: str, password: str):
        """
        Initialize SSH server.

        Args:
            root_path: Root path for SFTP operations
            username: Required username for authentication
            password: Required password for authentication
        """
        self._root_path = root_path
        self._username = username
        self._password = password
        self._conn = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        """Called when a connection is established."""
        self._conn = conn
        peername = conn.get_extra_info('peername')
        logger.info(f"SSH connection from {peername}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when connection is lost."""
        if exc:
            logger.warning(f"SSH connection lost: {exc}")
        else:
            logger.info("SSH connection closed cleanly")

    def begin_auth(self, username: str) -> bool:
        """Called when authentication begins - return True to require auth."""
        return True

    def password_auth_supported(self) -> bool:
        """Enable password authentication."""
        return True

    def validate_password(self, username: str, password: str) -> bool:
        """Validate username/password."""
        if username == self._username and password == self._password:
            logger.info(f"Authentication successful for user: {username}")
            return True
        logger.warning(f"Authentication failed for user: {username}")
        return False


def _create_sftp_server_factory(root_path: Path):
    """Create a factory function for SFTP server instances."""
    def factory(conn):
        return CUCMSFTPServer(conn, root_path)
    return factory


async def generate_host_key(key_path: Path) -> asyncssh.SSHKey:
    """
    Generate or load an SSH host key.

    Args:
        key_path: Path to the host key file

    Returns:
        SSH private key
    """
    if key_path.exists():
        logger.info(f"Loading existing host key from {key_path}")
        return asyncssh.read_private_key(str(key_path))

    logger.info(f"Generating new SSH host key at {key_path}")

    # Ensure directory exists
    key_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate RSA key (widely compatible with CUCM)
    key = asyncssh.generate_private_key('ssh-rsa', key_size=2048)

    # Save the key
    key_path.write_bytes(key.export_private_key())
    key_path.chmod(0o600)  # Restrict permissions

    logger.info(f"Generated new RSA host key: {key_path}")
    return key


async def generate_ecdsa_host_key(key_path: Path) -> asyncssh.SSHKey:
    """
    Generate or load an ECDSA SSH host key.

    CUCM's PKIX-modified OpenSSH may have issues with RSA signature
    algorithm negotiation. ECDSA avoids this entirely.

    Args:
        key_path: Path to the host key file

    Returns:
        SSH private key
    """
    if key_path.exists():
        logger.info(f"Loading existing ECDSA host key from {key_path}")
        return asyncssh.read_private_key(str(key_path))

    logger.info(f"Generating new ECDSA host key at {key_path}")

    key_path.parent.mkdir(parents=True, exist_ok=True)

    key = asyncssh.generate_private_key('ecdsa-sha2-nistp256')

    key_path.write_bytes(key.export_private_key())
    key_path.chmod(0o600)

    logger.info(f"Generated new ECDSA host key: {key_path}")
    return key


class EmbeddedSFTPServer:
    """
    Manages the embedded SFTP server lifecycle.

    Usage:
        server = EmbeddedSFTPServer(
            host='0.0.0.0',
            port=2222,
            root_path=Path('./storage/received'),
            username='cucm-collector',
            password='secret',
            host_key_path=Path('./storage/ssh_host_key')
        )
        await server.start()
        # ... application runs ...
        await server.stop()
    """

    def __init__(
        self,
        host: str,
        port: int,
        root_path: Path,
        username: str,
        password: str,
        host_key_path: Path
    ):
        """
        Initialize the SFTP server.

        Args:
            host: Host to bind to (usually 0.0.0.0)
            port: Port to listen on (default 2222 to avoid conflict with system SSH)
            root_path: Root directory for SFTP operations
            username: Username for authentication
            password: Password for authentication
            host_key_path: Path to SSH host key file
        """
        self._host = host
        self._port = port
        self._root_path = root_path.resolve()
        self._username = username
        self._password = password
        self._host_key_path = host_key_path
        self._server: Optional[asyncssh.SSHAcceptor] = None
        self._started = False

    async def start(self) -> None:
        """Start the SFTP server."""
        if self._started:
            logger.warning("SFTP server already started")
            return

        # Enable asyncssh debug logging to diagnose handshake issues
        asyncssh_logger = logging.getLogger('asyncssh')
        asyncssh_logger.setLevel(logging.DEBUG)

        # Ensure root path exists
        self._root_path.mkdir(parents=True, exist_ok=True)

        # Generate or load host keys (ECDSA + RSA for maximum compatibility)
        # ECDSA is preferred because CUCM's PKIX-modified OpenSSH may have
        # issues with RSA signature algorithm negotiation (rsa-sha2-256/512).
        # By offering ECDSA first, the key exchange avoids RSA complexity.
        ecdsa_key_path = self._host_key_path.parent / "ssh_host_ecdsa_key"
        ecdsa_key = await generate_ecdsa_host_key(ecdsa_key_path)
        rsa_key = await generate_host_key(self._host_key_path)

        host_keys = [ecdsa_key, rsa_key]
        logger.info(
            f"Host keys: {[k.get_algorithm() for k in host_keys]}"
        )

        # Create server factory
        def server_factory():
            return CUCMSSHServer(self._root_path, self._username, self._password)

        # Create SFTP server factory
        sftp_factory = _create_sftp_server_factory(self._root_path)

        try:
            self._server = await asyncssh.create_server(
                server_factory,
                host=self._host,
                port=self._port,
                server_host_keys=host_keys,
                sftp_factory=sftp_factory,
                process_factory=None,  # SFTP only, no shell
                # Explicitly include ssh-rsa signature for older SSH clients
                # that don't support rsa-sha2-256/512
                signature_algs=[
                    'ecdsa-sha2-nistp256',
                    'rsa-sha2-512',
                    'rsa-sha2-256',
                    'ssh-rsa',
                ],
            )

            self._started = True
            logger.info(
                f"Embedded SFTP server started on {self._host}:{self._port} "
                f"(root={self._root_path}, user={self._username})"
            )

        except OSError as e:
            if e.errno == 98:  # Address already in use
                logger.error(f"SFTP port {self._port} already in use. Check for conflicts.")
            raise

    async def stop(self) -> None:
        """Stop the SFTP server."""
        if not self._started or not self._server:
            return

        logger.info("Stopping embedded SFTP server...")
        self._server.close()
        await self._server.wait_closed()
        self._started = False
        logger.info("Embedded SFTP server stopped")

    @property
    def is_running(self) -> bool:
        """Check if server is running."""
        return self._started


# Global server instance (for use with FastAPI lifespan)
_sftp_server: Optional[EmbeddedSFTPServer] = None


async def start_sftp_server(
    host: str = '0.0.0.0',
    port: int = 2222,
    root_path: Path = None,
    username: str = None,
    password: str = None,
    host_key_path: Path = None
) -> EmbeddedSFTPServer:
    """
    Start the global SFTP server instance.

    This is a convenience function for use with FastAPI lifespan events.

    Args:
        host: Host to bind to
        port: Port to listen on
        root_path: Root directory for SFTP
        username: Username for auth
        password: Password for auth
        host_key_path: Path to host key

    Returns:
        The started server instance
    """
    global _sftp_server

    if _sftp_server and _sftp_server.is_running:
        logger.warning("SFTP server already running")
        return _sftp_server

    _sftp_server = EmbeddedSFTPServer(
        host=host,
        port=port,
        root_path=root_path,
        username=username,
        password=password,
        host_key_path=host_key_path
    )

    await _sftp_server.start()
    return _sftp_server


async def stop_sftp_server() -> None:
    """Stop the global SFTP server instance."""
    global _sftp_server

    if _sftp_server:
        await _sftp_server.stop()
        _sftp_server = None


def get_sftp_server() -> Optional[EmbeddedSFTPServer]:
    """Get the current SFTP server instance."""
    return _sftp_server
