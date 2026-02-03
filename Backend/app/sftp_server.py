"""
Embedded SFTP Server for CUCM Log Collector

This module manages an OpenSSH sshd process that provides SFTP service for
CUCM devices to push log files. It replaces the previous asyncssh-based
implementation which failed to complete SSH key exchange through Docker
Desktop's port forwarding on Windows.

The sshd process is started by entrypoint.sh before uvicorn launches.
This module provides monitoring and health-check functions used by
the FastAPI application (lifespan events and /health endpoint).

Architecture:
- entrypoint.sh: Generates host keys, sets SFTP user password, starts sshd
- sshd_config_sftp: OpenSSH config with CUCM-compatible legacy algorithms
- This module: Monitors sshd process, provides status to FastAPI
"""

import logging
import os
import signal
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Path to the sshd PID file (set in sshd_config_sftp)
SSHD_PID_FILE = Path("/tmp/sshd_sftp.pid")


def _get_sshd_pid() -> Optional[int]:
    """Read the sshd PID from the PID file."""
    try:
        if SSHD_PID_FILE.exists():
            pid_str = SSHD_PID_FILE.read_text().strip()
            if pid_str:
                return int(pid_str)
    except (ValueError, OSError) as e:
        logger.debug(f"Could not read sshd PID file: {e}")
    return None


def _is_process_running(pid: int) -> bool:
    """Check if a process with the given PID is running."""
    try:
        os.kill(pid, 0)  # Signal 0 = check existence, don't actually signal
        return True
    except OSError:
        return False


class EmbeddedSFTPServer:
    """
    Monitors the OpenSSH sshd process that provides SFTP service.

    The actual sshd process is started by entrypoint.sh at container startup.
    This class provides:
    - Health checking (is sshd running?)
    - Graceful stop on application shutdown
    - Status reporting for the /health endpoint
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
        self._host = host
        self._port = port
        self._root_path = root_path.resolve()
        self._username = username
        self._password = password
        self._host_key_path = host_key_path
        self._started = False

    async def start(self) -> None:
        """
        Verify that the sshd SFTP server is running.

        The sshd process is started by entrypoint.sh before uvicorn.
        This method checks that it's actually running and logs the status.
        """
        if self._started:
            logger.warning("SFTP server monitor already started")
            return

        # Ensure root path exists
        self._root_path.mkdir(parents=True, exist_ok=True)

        # Check if sshd is already running (started by entrypoint.sh)
        pid = _get_sshd_pid()
        if pid and _is_process_running(pid):
            self._started = True
            logger.info(
                f"OpenSSH SFTP server running (PID {pid}) on "
                f"{self._host}:{self._port} "
                f"(root={self._root_path}, user={self._username})"
            )
            return

        # sshd not running - try to start it (fallback for dev/non-Docker)
        logger.warning(
            "sshd not running (no PID file or process dead). "
            "Attempting to start sshd directly..."
        )
        sshd_config = Path("/app/sshd_config_sftp")
        if not sshd_config.exists():
            logger.error(
                f"sshd config not found at {sshd_config}. "
                "SFTP server will NOT be available. "
                "Ensure entrypoint.sh runs before uvicorn."
            )
            return

        try:
            result = subprocess.run(
                ["/usr/sbin/sshd", "-f", str(sshd_config)],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                pid = _get_sshd_pid()
                self._started = True
                logger.info(
                    f"Started sshd SFTP server (PID {pid}) on port {self._port}"
                )
            else:
                logger.error(
                    f"Failed to start sshd: exit={result.returncode} "
                    f"stderr={result.stderr.strip()}"
                )
        except FileNotFoundError:
            logger.error(
                "sshd binary not found. Install openssh-server in the container."
            )
        except subprocess.TimeoutExpired:
            logger.error("sshd startup timed out")
        except Exception as e:
            logger.error(f"Failed to start sshd: {e}")

    async def stop(self) -> None:
        """Stop the sshd SFTP server gracefully."""
        if not self._started:
            return

        pid = _get_sshd_pid()
        if pid and _is_process_running(pid):
            logger.info(f"Stopping sshd SFTP server (PID {pid})...")
            try:
                os.kill(pid, signal.SIGTERM)
                logger.info("sshd SFTP server stopped")
            except OSError as e:
                logger.warning(f"Error stopping sshd: {e}")

        self._started = False

    @property
    def is_running(self) -> bool:
        """Check if the sshd SFTP server is running."""
        pid = _get_sshd_pid()
        if pid and _is_process_running(pid):
            return True
        # If the process died, update our state
        if self._started:
            self._started = False
            logger.warning("sshd SFTP server is no longer running")
        return False


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
