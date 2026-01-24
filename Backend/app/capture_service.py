"""Packet capture service for CUCM, CSR1000v, and Expressway"""

import asyncio
import logging
import uuid
import re
from datetime import datetime, timezone
from typing import Dict, Optional, List
from pathlib import Path
from urllib.parse import quote as url_quote

from app.models import (
    StartCaptureRequest,
    CaptureInfo,
    CaptureStatus,
    CaptureDeviceType,
    CaptureFilter,
)
from app.ssh_client import (
    CUCMSSHClient,
    CUCMAuthError,
    CUCMConnectionError,
    CUCMCommandTimeoutError,
    CUCMSSHClientError,
)
from app.csr_client import (
    CSRSSHClient,
    CSRAuthError,
    CSRConnectionError,
    CSRCommandTimeoutError,
    CSRSSHClientError,
    build_epc_capture_config,
    build_epc_start_command,
    build_epc_stop_command,
    build_epc_export_command,
    build_epc_clear_command,
    parse_epc_status,
)
from app.expressway_client import (
    ExpresswayClient,
    ExpresswayAuthError,
    ExpresswayConnectionError,
    ExpresswayAPIError,
)
from app.config import get_settings
from app.prompt_responder import PromptResponder
from app.network_utils import get_local_ip_for_target


logger = logging.getLogger(__name__)


# SFTP prompt timeout for file retrieval
# Total timeout for SFTP file retrieval (prompts + transfer)
# Set to 5 minutes to allow: ~60s for prompts + 180s transfer timeout + buffer
SFTP_PROMPT_TIMEOUT = 300.0


def build_cucm_capture_command(
    interface: str,
    filename: str,
    count: int,
    capture_filter: Optional[CaptureFilter] = None,
) -> str:
    """
    Build the CUCM utils network capture command.

    Command syntax:
    utils network capture [eth0] [file fname] [count num] [size bytes|all]
                         [src addr] [dest addr] [port num] [host protocol addr]

    Args:
        interface: Network interface (e.g., eth0)
        filename: Capture filename (without extension)
        count: Maximum packet count
        capture_filter: Optional filter settings

    Returns:
        Complete capture command string
    """
    # Base command
    cmd_parts = [
        "utils network capture",
        interface,
        f"file {filename}",
        f"count {count}",
        "size all",  # Capture full packets
    ]

    # Add filters
    if capture_filter:
        if capture_filter.port:
            cmd_parts.append(f"port {capture_filter.port}")

        if capture_filter.host:
            protocol = capture_filter.protocol or "ip"
            cmd_parts.append(f"host {protocol} {capture_filter.host}")
        else:
            if capture_filter.src:
                cmd_parts.append(f"src {capture_filter.src}")
            if capture_filter.dest:
                cmd_parts.append(f"dest {capture_filter.dest}")

    return " ".join(cmd_parts)


def parse_capture_output(output: str) -> Dict:
    """
    Parse the output of a capture command to extract statistics.

    Args:
        output: Raw capture command output

    Returns:
        Dict with parsed statistics
    """
    stats = {
        "packets_captured": None,
        "packets_received": None,
        "packets_dropped": None,
    }

    # Try to parse packet count from output
    # Common patterns: "X packets captured", "X packets received"
    captured_match = re.search(r'(\d+)\s+packets?\s+captured', output, re.IGNORECASE)
    if captured_match:
        stats["packets_captured"] = int(captured_match.group(1))

    received_match = re.search(r'(\d+)\s+packets?\s+received', output, re.IGNORECASE)
    if received_match:
        stats["packets_received"] = int(received_match.group(1))

    dropped_match = re.search(r'(\d+)\s+packets?\s+dropped', output, re.IGNORECASE)
    if dropped_match:
        stats["packets_dropped"] = int(dropped_match.group(1))

    return stats


class Capture:
    """Represents a packet capture session"""

    def __init__(
        self,
        capture_id: str,
        request: StartCaptureRequest,
        filename: str,
    ):
        self.capture_id = capture_id
        self.request = request
        self.filename = filename
        self.status = CaptureStatus.PENDING
        self.device_type = request.device_type
        self.created_at = datetime.now(timezone.utc)
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error: Optional[str] = None
        self.message: Optional[str] = None
        self.file_size_bytes: Optional[int] = None
        self.packets_captured: Optional[int] = None
        self.local_file_path: Optional[Path] = None
        self._task: Optional[asyncio.Task] = None
        self._cancelled = False
        self._stop_event: asyncio.Event = asyncio.Event()

    def to_info(self) -> CaptureInfo:
        """Convert to CaptureInfo model"""
        return CaptureInfo(
            capture_id=self.capture_id,
            status=self.status,
            device_type=self.device_type,
            host=self.request.host,
            interface=self.request.interface,
            filename=self.filename,
            duration_sec=self.request.duration_sec,
            filter=self.request.filter,
            packet_count=self.request.packet_count,
            started_at=self.started_at,
            completed_at=self.completed_at,
            created_at=self.created_at,
            file_size_bytes=self.file_size_bytes,
            packets_captured=self.packets_captured,
            error=self.error,
            message=self.message,
        )

    def cancel(self):
        """Mark capture as cancelled and signal stop"""
        self._cancelled = True
        self._stop_event.set()  # Signal the capture to stop
        if self._task and not self._task.done():
            self._task.cancel()


class CaptureManager:
    """Manages packet capture sessions"""

    _instance: Optional["CaptureManager"] = None

    def __init__(self):
        self._captures: Dict[str, Capture] = {}
        self._storage_root: Optional[Path] = None

    @classmethod
    def get_instance(cls) -> "CaptureManager":
        """Get singleton instance"""
        if cls._instance is None:
            cls._instance = CaptureManager()
        return cls._instance

    @property
    def storage_root(self) -> Path:
        """Get storage root directory"""
        if self._storage_root is None:
            settings = get_settings()
            self._storage_root = Path(settings.storage_root) / "captures"
            self._storage_root.mkdir(parents=True, exist_ok=True)
        return self._storage_root

    def create_capture(self, request: StartCaptureRequest) -> Capture:
        """
        Create a new capture session.

        Args:
            request: Capture request parameters

        Returns:
            New Capture object
        """
        capture_id = str(uuid.uuid4())

        # Generate filename if not provided
        if request.filename:
            filename = request.filename
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"capture_{timestamp}"

        capture = Capture(
            capture_id=capture_id,
            request=request,
            filename=filename,
        )

        self._captures[capture_id] = capture
        logger.info(f"Created capture {capture_id} for host {request.host}")

        return capture

    def get_capture(self, capture_id: str) -> Optional[Capture]:
        """Get a capture by ID"""
        return self._captures.get(capture_id)

    def list_captures(self, limit: int = 50) -> List[Capture]:
        """List recent captures"""
        captures = sorted(
            self._captures.values(),
            key=lambda c: c.created_at,
            reverse=True
        )
        return captures[:limit]

    def delete_capture(self, capture_id: str) -> bool:
        """
        Delete a capture and its files.

        Args:
            capture_id: Capture identifier

        Returns:
            True if deleted, False if not found
        """
        capture = self._captures.get(capture_id)
        if not capture:
            return False

        # Cancel if running
        if capture.status == CaptureStatus.RUNNING:
            capture.cancel()

        # Delete local file if exists
        if capture.local_file_path and capture.local_file_path.exists():
            try:
                capture.local_file_path.unlink()
                logger.info(f"Deleted capture file: {capture.local_file_path}")
            except Exception as e:
                logger.warning(f"Failed to delete capture file: {e}")

        del self._captures[capture_id]
        logger.info(f"Deleted capture {capture_id}")
        return True

    async def execute_capture(self, capture_id: str) -> None:
        """
        Execute a packet capture - routes to appropriate method based on device type.

        Args:
            capture_id: Capture identifier
        """
        capture = self._captures.get(capture_id)
        if not capture:
            logger.error(f"Capture {capture_id} not found")
            return

        # Route based on device type
        if capture.device_type == CaptureDeviceType.CSR1000V:
            await self._execute_csr_capture(capture_id)
        elif capture.device_type == CaptureDeviceType.EXPRESSWAY:
            await self._execute_expressway_capture(capture_id)
        else:
            # CUCM is the default
            await self._execute_cucm_capture(capture_id)

    async def _execute_cucm_capture(self, capture_id: str) -> None:
        """
        Execute a packet capture on CUCM.

        This runs the capture command on the CUCM node, waits for the
        specified duration (or until stopped), then retrieves the capture file.

        Args:
            capture_id: Capture identifier
        """
        capture = self._captures.get(capture_id)
        if not capture:
            logger.error(f"Capture {capture_id} not found")
            return

        request = capture.request
        capture.status = CaptureStatus.RUNNING
        capture.started_at = datetime.now(timezone.utc)
        capture.message = "Starting capture..."

        logger.info(
            f"Starting CUCM capture {capture_id} on {request.host} "
            f"for {request.duration_sec}s"
        )

        try:
            # Build the capture command
            cmd = build_cucm_capture_command(
                interface=request.interface,
                filename=capture.filename,
                count=request.packet_count,
                capture_filter=request.filter,
            )

            logger.debug(f"Capture command: {cmd}")

            # Connect and run capture
            async with CUCMSSHClient(
                host=request.host,
                port=request.port,
                username=request.username,
                password=request.password,
                connect_timeout=float(request.connect_timeout_sec),
            ) as client:
                capture.message = "Capturing packets..."

                # Send the capture command WITHOUT waiting for prompt
                # The capture runs until Ctrl+C is sent
                await client.send_command_no_wait(cmd)

                # Wait for either:
                # 1. Duration to elapse
                # 2. Stop event to be set (user stopped capture)
                try:
                    await asyncio.wait_for(
                        capture._stop_event.wait(),
                        timeout=float(request.duration_sec)
                    )
                    # Stop event was set - user requested stop
                    logger.info(f"Capture {capture_id} stopped by user")
                except asyncio.TimeoutError:
                    # Duration elapsed - normal completion
                    logger.info(f"Capture {capture_id} duration reached")

                # Update status to STOPPING so frontend knows capture phase is done
                capture.status = CaptureStatus.STOPPING

                # Send Ctrl+C to stop the capture
                capture.message = "Stopping capture..."
                await client.send_interrupt()

                # Wait a moment for CUCM to process the interrupt
                await asyncio.sleep(1.0)

                # Read the output until we get the prompt back
                # After Ctrl+C, the session might need recovery if prompt isn't seen
                output = ""
                try:
                    output = await client.read_until_prompt(timeout=30.0)
                    logger.debug(f"Capture output: {output[:200]}...")

                    # Parse capture statistics
                    stats = parse_capture_output(output)
                    capture.packets_captured = stats.get("packets_captured")
                    logger.info(
                        f"Capture {capture_id} stats: "
                        f"{capture.packets_captured or 'unknown'} packets captured"
                    )
                except Exception as e:
                    logger.warning(f"Failed to read capture output: {e}")
                    # Try to recover the session by sending newline and waiting for prompt
                    logger.info(f"Attempting session recovery for {capture_id}")
                    try:
                        await client.recover_session()
                        logger.info(f"Session recovered for {capture_id}")
                    except Exception as recovery_error:
                        logger.warning(f"Session recovery failed: {recovery_error}")

                # Check for cancellation/stop before file retrieval
                if capture._cancelled or capture._stop_event.is_set():
                    logger.info(f"Capture {capture_id} stopped before file retrieval")
                    capture.status = CaptureStatus.STOPPED
                    capture.message = "Capture stopped by user"
                    capture.completed_at = datetime.now(timezone.utc)
                    return

                # Give CUCM a moment to finish writing the capture file
                await asyncio.sleep(2.0)

                # Check again after sleep
                if capture._cancelled or capture._stop_event.is_set():
                    logger.info(f"Capture {capture_id} stopped before file retrieval")
                    capture.status = CaptureStatus.STOPPED
                    capture.message = "Capture stopped by user"
                    capture.completed_at = datetime.now(timezone.utc)
                    return

                # Retrieve the capture file
                capture.message = "Retrieving capture file..."
                settings = get_settings()
                if settings.sftp_relay_mode:
                    # Relay mode: CUCM uploads to relay server, then we pull from relay
                    logger.info("Using SFTP relay mode (CUCM -> relay -> local)")
                    await self._retrieve_capture_file_relay(client, capture)
                else:
                    # Direct mode: CUCM uploads to our embedded SFTP server
                    logger.info("Using SFTP direct mode (CUCM uploads to embedded server)")
                    await self._retrieve_capture_file(client, capture)

                # Mark as completed
                capture.status = CaptureStatus.COMPLETED
                capture.completed_at = datetime.now(timezone.utc)
                capture.message = "Capture completed successfully"

                logger.info(
                    f"Capture {capture_id} completed: "
                    f"{capture.packets_captured or 'unknown'} packets, "
                    f"{capture.file_size_bytes or 0} bytes"
                )

        except CUCMAuthError as e:
            logger.error(f"Capture {capture_id} auth failed: {e}")
            capture.status = CaptureStatus.FAILED
            capture.error = f"Authentication failed: {e}"
            capture.message = "Authentication failed"

        except CUCMConnectionError as e:
            logger.error(f"Capture {capture_id} connection failed: {e}")
            capture.status = CaptureStatus.FAILED
            capture.error = f"Connection failed: {e}"
            capture.message = "Connection failed"

        except CUCMCommandTimeoutError as e:
            logger.error(f"Capture {capture_id} command timeout: {e}")
            capture.status = CaptureStatus.FAILED
            capture.error = f"Command timeout: {e}"
            capture.message = "Command timeout"

        except asyncio.CancelledError:
            logger.info(f"Capture {capture_id} cancelled")
            capture.status = CaptureStatus.CANCELLED
            capture.message = "Capture cancelled"

        except Exception as e:
            logger.exception(f"Capture {capture_id} failed: {e}")
            capture.status = CaptureStatus.FAILED
            capture.error = str(e)
            capture.message = "Capture failed"

        finally:
            if not capture.completed_at:
                capture.completed_at = datetime.now(timezone.utc)

    async def _retrieve_capture_file(
        self,
        client: CUCMSSHClient,
        capture: Capture
    ) -> None:
        """
        Retrieve the capture file from CUCM via SFTP.

        The capture file is stored at: activelog/platform/cli/<filename>.cap

        We use 'file get activelog' command which prompts for SFTP details
        and transfers the file to our SFTP server.

        Args:
            client: Connected SSH client
            capture: Capture object to update
        """
        settings = get_settings()
        capture_file = f"{capture.filename}.cap"
        remote_path = f"platform/cli/{capture_file}"

        try:
            # Check if stop was requested before starting retrieval
            if capture._stop_event.is_set() or capture._cancelled:
                logger.info(f"Capture {capture.capture_id} stop requested, skipping file retrieval")
                return

            # First, list the file to verify it exists and get size
            list_cmd = f"file list activelog {remote_path} detail"
            logger.info(f"Listing capture file: {list_cmd}")
            output = await client.execute_command(list_cmd, timeout=30.0)
            logger.debug(f"File list output: {output[:200] if output else 'empty'}")

            # Parse file size from output
            # Format: "12345  Jan 02 16:30  filename.cap"
            size_match = re.search(r'^\s*(\d+)\s+', output, re.MULTILINE)
            if size_match:
                capture.file_size_bytes = int(size_match.group(1))
                logger.debug(f"Capture file size: {capture.file_size_bytes} bytes")

            # Build SFTP directory path (what CUCM sees)
            sftp_base = settings.sftp_remote_base_dir or ""
            sftp_directory = f"{sftp_base}/{capture.capture_id}".strip("/")

            # Create directory at SFTP received location for CUCM to upload to
            # Handle both possible bind mount configurations:
            # 1. Bind mount at /received/ level: files land at artifacts_dir/<capture_id>/
            # 2. Bind mount at chroot level: files land at artifacts_dir/<sftp_base>/<capture_id>/
            sftp_upload_dir = settings.artifacts_dir / capture.capture_id
            sftp_upload_dir_nested = settings.artifacts_dir / sftp_directory if sftp_base else None

            try:
                sftp_upload_dir.mkdir(parents=True, exist_ok=True)
                sftp_upload_dir.chmod(0o777)
                logger.info(f"Created SFTP upload directory: {sftp_upload_dir}")

                # Also create nested path if sftp_base is set
                if sftp_upload_dir_nested and sftp_upload_dir_nested != sftp_upload_dir:
                    sftp_upload_dir_nested.mkdir(parents=True, exist_ok=True)
                    sftp_upload_dir_nested.chmod(0o777)
                    logger.info(f"Created nested SFTP directory: {sftp_upload_dir_nested}")
            except Exception as e:
                logger.warning(f"Failed to create SFTP upload directory: {e}")

            # Check again before starting SFTP transfer
            if capture._stop_event.is_set() or capture._cancelled:
                logger.info(f"Capture {capture.capture_id} stop requested, skipping SFTP transfer")
                return

            # Determine the best SFTP host IP to use
            # Priority: 1) Explicitly configured SFTP_HOST, 2) Auto-detect for target
            target_host = capture.request.host

            # Check if SFTP_HOST was explicitly configured (not auto-detected)
            if settings.sftp_host:
                # User explicitly set SFTP_HOST - use it (e.g., VPN IP)
                sftp_host = settings.sftp_host
                logger.info(f"Using configured SFTP host: {sftp_host}")
            else:
                # Auto-detect: find the local IP that can reach the CUCM target
                sftp_host = get_local_ip_for_target(target_host)
                if not sftp_host:
                    # Fall back to general auto-detection
                    sftp_host = settings.effective_sftp_host
                    logger.warning(f"Could not detect local IP for target {target_host}, using {sftp_host}")
                else:
                    logger.info(f"Using auto-detected SFTP host {sftp_host} (for target {target_host})")

            # Set up prompt responder for SFTP transfer
            responder = PromptResponder(
                sftp_host=sftp_host,
                sftp_port=settings.sftp_port,
                sftp_username=settings.sftp_username,
                sftp_password=settings.sftp_password,
                sftp_directory=sftp_directory,
            )

            # Run file get command with prompt responding
            get_cmd = f"file get activelog {remote_path}"
            logger.debug(f"Running: {get_cmd}")

            # Get the shell session for interactive command
            shell = client._session
            if shell:
                # Send the command
                shell.stdin.write(f"{get_cmd}\n")
                await shell.stdin.drain()

                # Handle prompts with timeout
                # respond_to_prompts expects (stdin, stdout) separately
                # Pass stop_event so transfer can be interrupted by user
                await asyncio.wait_for(
                    responder.respond_to_prompts(
                        shell.stdin,
                        shell.stdout,
                        stop_event=capture._stop_event,
                        transfer_timeout=180.0  # 3 min timeout for SFTP transfer
                    ),
                    timeout=SFTP_PROMPT_TIMEOUT
                )

            # Wait for SFTP transfer to complete
            await asyncio.sleep(2.0)

            # Search for the capture file recursively
            # CUCM preserves directory structure: <capture_id>/<host>/<timestamp>/platform/cli/<file>.cap
            found_file = None

            # Search in primary upload directory
            for cap_file in sftp_upload_dir.rglob(capture_file):
                found_file = cap_file
                logger.info(f"Found capture file at: {found_file}")
                break

            # If not found, try nested directory
            if not found_file and sftp_upload_dir_nested:
                for cap_file in sftp_upload_dir_nested.rglob(capture_file):
                    found_file = cap_file
                    logger.info(f"Found capture file at nested path: {found_file}")
                    break

            if found_file:
                capture.local_file_path = found_file
                capture.file_size_bytes = found_file.stat().st_size
                capture.message = f"Capture file retrieved: {capture_file}"
                logger.info(f"Retrieved capture file: {found_file} ({capture.file_size_bytes} bytes)")
            else:
                # File not found
                logger.warning(f"Capture file {capture_file} not found in {sftp_upload_dir}")
                capture.message = f"Capture complete, file retrieval pending"

        except (asyncio.TimeoutError, CUCMCommandTimeoutError) as e:
            logger.warning(f"Timeout retrieving capture file for {capture.capture_id}: {e}")
            capture.message = "Capture complete, file retrieval timed out"

        except Exception as e:
            logger.warning(f"Failed to retrieve capture file: {e}")
            capture.message = f"Capture complete, file retrieval failed: {e}"

    async def _retrieve_capture_file_pull(
        self,
        client: CUCMSSHClient,
        capture: Capture
    ) -> None:
        """
        Retrieve the capture file by pulling FROM CUCM's SFTP server.

        This method connects to CUCM's built-in SFTP server and downloads
        the capture file directly. This works in VPN/NAT scenarios where
        CUCM cannot connect back to the client.

        The capture file is stored at: activelog/platform/cli/<filename>.cap

        Args:
            client: Connected SSH client (used for credentials)
            capture: Capture object to update
        """
        import asyncssh

        settings = get_settings()
        capture_file = f"{capture.filename}.cap"
        # CUCM SFTP uses paths relative to root, try without leading slash
        remote_path = f"activelog/platform/cli/{capture_file}"

        try:
            # Check if stop was requested before starting retrieval
            if capture._stop_event.is_set() or capture._cancelled:
                logger.info(f"Capture {capture.capture_id} stop requested, skipping file retrieval")
                return

            # Create local directory for the capture file
            local_dir = settings.artifacts_dir / capture.capture_id
            local_dir.mkdir(parents=True, exist_ok=True)
            local_file = local_dir / capture_file

            logger.info(f"Pulling capture file via SFTP from CUCM: {remote_path}")

            # Connect to CUCM's SFTP server using same credentials as SSH
            host = capture.request.host
            port = capture.request.port or 22
            username = capture.request.username
            password = capture.request.password

            # Use asyncssh to connect and download the file
            async with asyncssh.connect(
                host=host,
                port=port,
                username=username,
                password=password,
                known_hosts=None,  # Accept any host key (like SSH client)
            ) as conn:
                async with conn.start_sftp_client() as sftp:
                    # Check if stop was requested
                    if capture._stop_event.is_set() or capture._cancelled:
                        logger.info(f"Capture {capture.capture_id} stop requested during SFTP")
                        return

                    # Try to stat the file first to verify it exists
                    try:
                        file_stat = await sftp.stat(remote_path)
                        logger.info(f"Found capture file: {remote_path}, size: {file_stat.size} bytes")
                    except asyncssh.SFTPNoSuchFile:
                        # Try with leading slash
                        remote_path = f"/{remote_path}"
                        logger.info(f"Trying alternate path: {remote_path}")
                        file_stat = await sftp.stat(remote_path)
                        logger.info(f"Found capture file: {remote_path}, size: {file_stat.size} bytes")

                    logger.info(f"SFTP connected, downloading {remote_path} to {local_file}")

                    # Download the file with block_size to handle large files
                    await sftp.get(remote_path, str(local_file), block_size=65536)

                    logger.info(f"SFTP download complete: {local_file}")

            # Verify file was downloaded
            if local_file.exists():
                capture.local_file_path = local_file
                capture.file_size_bytes = local_file.stat().st_size
                capture.message = f"Capture file retrieved: {capture_file}"
                logger.info(f"Retrieved capture file: {local_file} ({capture.file_size_bytes} bytes)")
            else:
                logger.warning(f"Capture file not found after download: {local_file}")
                capture.message = "Capture complete, file download failed"

        except asyncssh.SFTPError as e:
            logger.warning(f"SFTP error retrieving capture file: {e}")
            capture.message = f"Capture complete, SFTP error: {e}"

        except asyncssh.PermissionDenied as e:
            logger.warning(f"SFTP permission denied: {e}")
            capture.message = "Capture complete, SFTP permission denied"

        except asyncio.TimeoutError:
            logger.warning(f"Timeout pulling capture file for {capture.capture_id}")
            capture.message = "Capture complete, file download timed out"

        except Exception as e:
            logger.warning(f"Failed to pull capture file: {e}")
            capture.message = f"Capture complete, file retrieval failed: {e}"

    async def _retrieve_capture_file_relay(
        self,
        client: CUCMSSHClient,
        capture: Capture
    ) -> None:
        """
        Retrieve capture file using a relay SFTP server.

        This method works for VPN scenarios where CUCM cannot reach the local machine:
        1. CUCM uploads the file to an external relay SFTP server
        2. App downloads the file from the relay server to local storage

        Args:
            client: Connected SSH client
            capture: Capture object to update
        """
        import asyncssh

        settings = get_settings()
        capture_file = f"{capture.filename}.cap"
        remote_path = f"platform/cli/{capture_file}"

        try:
            # Check if stop was requested
            if capture._stop_event.is_set() or capture._cancelled:
                logger.info(f"Capture {capture.capture_id} stop requested, skipping file retrieval")
                return

            # Relay server settings
            relay_host = settings.sftp_host
            relay_port = settings.sftp_port
            relay_username = settings.sftp_username
            relay_password = settings.sftp_password

            if not relay_host:
                raise ValueError("SFTP_HOST must be configured for relay mode")

            # Build relay directory path
            sftp_base = settings.sftp_remote_base_dir or ""
            relay_directory = f"{sftp_base}/{capture.capture_id}".strip("/")

            logger.info(f"Relay mode: CUCM will upload to {relay_host}:{relay_port}/{relay_directory}")

            # Set up prompt responder to tell CUCM to upload to relay server
            responder = PromptResponder(
                sftp_host=relay_host,
                sftp_port=relay_port,
                sftp_username=relay_username,
                sftp_password=relay_password,
                sftp_directory=relay_directory,
            )

            # Run file get command with prompt responding
            get_cmd = f"file get activelog {remote_path}"
            logger.info(f"Running: {get_cmd}")

            # Get the shell session for interactive command
            shell = client._session
            if shell:
                # Send the command
                shell.stdin.write(f"{get_cmd}\n")
                await shell.stdin.drain()

                # Handle prompts with timeout
                await asyncio.wait_for(
                    responder.respond_to_prompts(
                        shell.stdin,
                        shell.stdout,
                        stop_event=capture._stop_event,
                        transfer_timeout=180.0
                    ),
                    timeout=SFTP_PROMPT_TIMEOUT
                )

            # Wait for SFTP transfer to complete
            logger.info("CUCM upload to relay complete, now downloading from relay...")
            await asyncio.sleep(2.0)

            # Check if stop was requested
            if capture._stop_event.is_set() or capture._cancelled:
                logger.info(f"Capture {capture.capture_id} stop requested during relay download")
                return

            # Now download the file from the relay server
            local_dir = settings.artifacts_dir / capture.capture_id
            local_dir.mkdir(parents=True, exist_ok=True)
            local_file = local_dir / capture_file

            # The file on relay will be at: relay_directory/<host>/<timestamp>/platform/cli/<file>.cap
            # Or directly at: relay_directory/<file>.cap depending on CUCM behavior
            # We'll search for it

            logger.info(f"Connecting to relay server {relay_host}:{relay_port} to download file")

            try:
                async with asyncio.timeout(60):  # 60 second timeout for relay download
                    async with asyncssh.connect(
                        host=relay_host,
                        port=relay_port,
                        username=relay_username,
                        password=relay_password,
                        known_hosts=None,
                    ) as conn:
                        logger.info("Connected to relay server")
                        async with conn.start_sftp_client() as sftp:
                            logger.info("SFTP client started, searching for file...")

                            # Search for the capture file
                            # CUCM creates: <relay_directory>/<host>/<timestamp>/platform/cli/<file>.cap
                            relay_file_path = None

                            # First, try direct path in case CUCM put it there
                            direct_path = f"{relay_directory}/{capture_file}"
                            try:
                                await sftp.stat(direct_path)
                                relay_file_path = direct_path
                                logger.info(f"Found file at direct path: {direct_path}")
                            except:
                                logger.debug(f"File not at direct path: {direct_path}")

                            # If not found, list the directory and search
                            if not relay_file_path:
                                logger.info(f"Listing relay directory: {relay_directory}")
                                try:
                                    # List the relay directory
                                    entries = await sftp.readdir(relay_directory)
                                    logger.info(f"Found {len(entries)} entries in {relay_directory}")

                                    for entry in entries:
                                        logger.debug(f"  Entry: {entry.filename}")
                                        # CUCM puts files in: <host>/<timestamp>/platform/cli/<file>.cap
                                        # Try to find the .cap file recursively (simplified)
                                        subdir = f"{relay_directory}/{entry.filename}"
                                        try:
                                            sub_entries = await sftp.readdir(subdir)
                                            for sub in sub_entries:
                                                # Check platform/cli path
                                                cli_path = f"{subdir}/{sub.filename}/platform/cli/{capture_file}"
                                                try:
                                                    await sftp.stat(cli_path)
                                                    relay_file_path = cli_path
                                                    logger.info(f"Found file at: {cli_path}")
                                                    break
                                                except:
                                                    pass
                                            if relay_file_path:
                                                break
                                        except:
                                            pass
                                except Exception as e:
                                    logger.warning(f"Error listing {relay_directory}: {e}")

                            if relay_file_path:
                                logger.info(f"Downloading from relay: {relay_file_path}")
                                await sftp.get(relay_file_path, str(local_file))
                                logger.info(f"Downloaded from relay to {local_file}")

                                # Verify file
                                if local_file.exists():
                                    capture.local_file_path = local_file
                                    capture.file_size_bytes = local_file.stat().st_size
                                    capture.message = f"Capture file retrieved: {capture_file}"
                                    logger.info(f"Retrieved capture file: {local_file} ({capture.file_size_bytes} bytes)")

                                    # Optionally delete from relay to save space
                                    try:
                                        await sftp.remove(relay_file_path)
                                        logger.info(f"Cleaned up relay file: {relay_file_path}")
                                    except Exception as e:
                                        logger.debug(f"Could not delete relay file: {e}")
                                else:
                                    logger.warning(f"File not found after download: {local_file}")
                                    capture.message = "Capture complete, relay download failed"
                            else:
                                logger.warning(f"Capture file not found on relay server")
                                capture.message = "Capture complete, file not found on relay"
            except asyncio.TimeoutError:
                logger.warning(f"Timeout connecting to relay server")
                capture.message = "Capture complete, relay connection timed out"

        except asyncio.TimeoutError:
            logger.warning(f"Timeout during relay transfer for {capture.capture_id}")
            capture.message = "Capture complete, relay transfer timed out"

        except Exception as e:
            logger.warning(f"Failed to retrieve capture file via relay: {e}")
            capture.message = f"Capture complete, relay transfer failed: {e}"

    async def _execute_csr_capture(self, capture_id: str) -> None:
        """
        Execute a packet capture on CSR1000v using IOS-XE EPC.

        This configures EPC, starts capture, waits for duration,
        stops capture, and exports the file via SCP.

        Args:
            capture_id: Capture identifier
        """
        capture = self._captures.get(capture_id)
        if not capture:
            logger.error(f"Capture {capture_id} not found")
            return

        request = capture.request
        capture.status = CaptureStatus.RUNNING
        capture.started_at = datetime.now(timezone.utc)
        capture.message = "Starting capture..."

        # Generate a unique capture name for EPC (max 8 chars, alphanumeric only)
        # IOS-XE EPC has strict 8-character limit
        capture_name = capture_id[:8].replace("-", "")
        pcap_filename = f"{capture.filename}.pcap"

        logger.info(
            f"Starting CSR capture {capture_id} on {request.host} "
            f"for {request.duration_sec}s"
        )

        settings = get_settings()

        try:
            # Build EPC configuration commands
            config_filter = request.filter
            config_commands = build_epc_capture_config(
                capture_name=capture_name,
                interface=request.interface,
                buffer_size_mb=10,  # 10MB buffer
                src_ip=config_filter.src if config_filter else None,
                dst_ip=config_filter.dest if config_filter else None,
                port=config_filter.port if config_filter else None,
                protocol=config_filter.protocol if config_filter else None,
            )

            # Connect and run capture
            async with CSRSSHClient(
                host=request.host,
                port=request.port,
                username=request.username,
                password=request.password,
                connect_timeout=float(request.connect_timeout_sec),
            ) as client:
                capture.message = "Configuring capture..."

                # Run configuration commands
                for cmd in config_commands:
                    logger.info(f"EPC config: {cmd}")
                    output = await client.execute_command(cmd, timeout=30.0)
                    output_clean = output.strip() if output else "(empty)"
                    logger.info(f"EPC config output: {output_clean[:200]}")
                    # Check for errors in configuration
                    if output and ("error" in output.lower() or "invalid" in output.lower()):
                        logger.error(f"EPC configuration failed: {output}")
                        raise CSRSSHClientError(f"EPC configuration failed: {output[:200]}")

                # Start the capture
                capture.message = "Capturing packets..."
                start_cmd = build_epc_start_command(capture_name)
                logger.info(f"Starting EPC: {start_cmd}")
                start_output = await client.execute_command(start_cmd, timeout=30.0)
                logger.info(f"Start output: {start_output.strip() if start_output else '(empty)'}")

                # Wait for either:
                # 1. Duration to elapse
                # 2. Stop event to be set (user stopped capture)
                try:
                    await asyncio.wait_for(
                        capture._stop_event.wait(),
                        timeout=float(request.duration_sec)
                    )
                    logger.info(f"Capture {capture_id} stopped by user")
                except asyncio.TimeoutError:
                    logger.info(f"Capture {capture_id} duration reached")

                # Stop the capture
                capture.message = "Stopping capture..."
                stop_cmd = build_epc_stop_command(capture_name)
                logger.info(f"Stopping EPC: {stop_cmd}")
                stop_output = await client.execute_command(stop_cmd, timeout=30.0)
                logger.info(f"Stop output: {stop_output.strip() if stop_output else '(empty)'}")

                # Check capture status
                status_cmd = f"show monitor capture {capture_name}"
                logger.info(f"Checking status: {status_cmd}")
                status_output = await client.execute_command(status_cmd, timeout=30.0)
                logger.info(f"Status output: {status_output.strip()[:300] if status_output else '(empty)'}")
                status = parse_epc_status(status_output)
                capture.packets_captured = status.get("packets")
                logger.info(
                    f"Capture {capture_id} stats: "
                    f"{capture.packets_captured or 'unknown'} packets captured"
                )

                # Check for cancellation before file retrieval
                if capture._cancelled:
                    # Clean up capture point
                    clear_cmd = build_epc_clear_command(capture_name)
                    await client.execute_command(clear_cmd, timeout=30.0)
                    capture.status = CaptureStatus.CANCELLED
                    capture.message = "Capture cancelled"
                    capture.completed_at = datetime.now(timezone.utc)
                    return

                # Export the capture file via SCP
                capture.message = "Retrieving capture file..."

                # For CSR/IOS-XE SCP export, put files directly in received/
                # IOS-XE SCP cannot create directories, so we use flat structure
                # with capture_id in the filename
                sftp_upload_dir = settings.artifacts_dir
                sftp_upload_dir.mkdir(parents=True, exist_ok=True)

                # Build SCP path - put file directly in received/ directory
                # Use capture_id prefix in filename for uniqueness
                scp_filename = f"{capture.capture_id[:8]}_{pcap_filename}"
                sftp_base = settings.sftp_remote_base_dir or ""
                if sftp_base:
                    scp_remote_path = f"{sftp_base}/{scp_filename}"
                else:
                    scp_remote_path = scp_filename

                # Build SCP URL: scp://user:pass@host/path/file.pcap
                # URL-encode the password to handle special characters like ! @ # etc.
                encoded_password = url_quote(settings.sftp_password, safe='')
                scp_url = (
                    f"scp://{settings.sftp_username}:{encoded_password}"
                    f"@{settings.effective_sftp_host}/{scp_remote_path}"
                )

                export_cmd = build_epc_export_command(capture_name, scp_url)
                logger.info(f"Exporting capture via SCP to {settings.effective_sftp_host}")
                logger.debug(f"SCP path: {scp_remote_path}")
                try:
                    output = await client.execute_command(export_cmd, timeout=120.0)
                    logger.info(f"Export command output: {output.strip() if output else '(empty)'}")

                    # Check for common error patterns in the output
                    output_lower = output.lower() if output else ""
                    # Check for success first (IOS-XE may show both "failed" and "Exported Successfully")
                    if "exported successfully" in output_lower:
                        logger.info("SCP export successful")
                    elif "permission denied" in output_lower:
                        logger.error(f"SCP permission denied - check server config")
                        capture.error = "SCP permission denied - server may require SCP config"
                    elif "connection refused" in output_lower:
                        logger.error(f"SCP connection refused")
                        capture.error = "SCP connection refused"
                    elif "error" in output_lower or "failed" in output_lower:
                        logger.error(f"SCP export reported error: {output}")
                        capture.error = f"SCP export failed: {output[:200]}"
                    else:
                        # No error indicators - assume success
                        logger.info("SCP export appears successful")
                except CSRCommandTimeoutError:
                    logger.warning("Export command timed out, file may still be transferring")

                # Clean up capture point
                clear_cmd = build_epc_clear_command(capture_name)
                await client.execute_command(clear_cmd, timeout=30.0)

                # Wait for file transfer to complete
                await asyncio.sleep(2.0)

                # Search for the capture file (use scp_filename we exported)
                found_file = None
                expected_path = sftp_upload_dir / scp_filename
                logger.info(f"Looking for capture file at: {expected_path}")

                if expected_path.exists():
                    found_file = expected_path
                    logger.info(f"Found capture file at: {found_file}")
                else:
                    # Also search recursively in case of different structure
                    for pcap in sftp_upload_dir.rglob(f"*{pcap_filename}"):
                        found_file = pcap
                        logger.info(f"Found capture file via search: {found_file}")
                        break

                if found_file:
                    capture.local_file_path = found_file
                    capture.file_size_bytes = found_file.stat().st_size
                    capture.message = f"Capture file retrieved: {scp_filename}"
                    logger.info(f"Retrieved capture file: {found_file} ({capture.file_size_bytes} bytes)")
                else:
                    logger.warning(f"Capture file {scp_filename} not found in {sftp_upload_dir}")
                    # List what files ARE in the directory
                    try:
                        files = list(sftp_upload_dir.iterdir())
                        logger.info(f"Files in {sftp_upload_dir}: {[f.name for f in files[:10]]}")
                    except Exception as e:
                        logger.debug(f"Could not list directory: {e}")
                    capture.message = "Capture complete, file retrieval pending"

                # Mark as completed
                capture.status = CaptureStatus.COMPLETED
                capture.completed_at = datetime.now(timezone.utc)
                if not capture.message.startswith("Capture file"):
                    capture.message = "Capture completed successfully"

                logger.info(
                    f"Capture {capture_id} completed: "
                    f"{capture.packets_captured or 'unknown'} packets, "
                    f"{capture.file_size_bytes or 0} bytes"
                )

        except CSRAuthError as e:
            logger.error(f"Capture {capture_id} auth failed: {e}")
            capture.status = CaptureStatus.FAILED
            capture.error = f"Authentication failed: {e}"
            capture.message = "Authentication failed"

        except CSRConnectionError as e:
            logger.error(f"Capture {capture_id} connection failed: {e}")
            capture.status = CaptureStatus.FAILED
            capture.error = f"Connection failed: {e}"
            capture.message = "Connection failed"

        except CSRCommandTimeoutError as e:
            logger.error(f"Capture {capture_id} command timeout: {e}")
            capture.status = CaptureStatus.FAILED
            capture.error = f"Command timeout: {e}"
            capture.message = "Command timeout"

        except asyncio.CancelledError:
            logger.info(f"Capture {capture_id} cancelled")
            capture.status = CaptureStatus.CANCELLED
            capture.message = "Capture cancelled"

        except Exception as e:
            logger.exception(f"Capture {capture_id} failed: {e}")
            capture.status = CaptureStatus.FAILED
            capture.error = str(e)
            capture.message = "Capture failed"

        finally:
            if not capture.completed_at:
                capture.completed_at = datetime.now(timezone.utc)

    async def _execute_expressway_capture(self, capture_id: str) -> None:
        """
        Execute a packet capture on Cisco Expressway using REST API.

        This uses the diagnostic logging API to start tcpdump,
        waits for duration, stops capture, collects logs, and
        downloads the pcap file.

        Args:
            capture_id: Capture identifier
        """
        capture = self._captures.get(capture_id)
        if not capture:
            logger.error(f"Capture {capture_id} not found")
            return

        request = capture.request
        capture.status = CaptureStatus.RUNNING
        capture.started_at = datetime.now(timezone.utc)
        capture.message = "Starting capture..."

        logger.info(
            f"Starting Expressway capture {capture_id} on {request.host} "
            f"for {request.duration_sec}s"
        )

        try:
            # Connect to Expressway REST API
            async with ExpresswayClient(
                host=request.host,
                username=request.username,
                password=request.password,
                port=request.port or 443,
            ) as client:
                capture.message = "Starting diagnostic logging..."

                # Start diagnostic logging with tcpdump
                await client.start_diagnostic_logging(tcpdump=True)

                capture.message = "Capturing packets..."

                # Wait for either:
                # 1. Duration to elapse
                # 2. Stop event to be set (user stopped capture)
                try:
                    await asyncio.wait_for(
                        capture._stop_event.wait(),
                        timeout=float(request.duration_sec)
                    )
                    logger.info(f"Capture {capture_id} stopped by user")
                except asyncio.TimeoutError:
                    logger.info(f"Capture {capture_id} duration reached")

                # Check for cancellation
                if capture._cancelled:
                    # Stop diagnostic logging without collecting
                    await client.stop_diagnostic_logging()
                    capture.status = CaptureStatus.CANCELLED
                    capture.message = "Capture cancelled"
                    capture.completed_at = datetime.now(timezone.utc)
                    return

                # Stop diagnostic logging
                capture.message = "Stopping capture..."
                await client.stop_diagnostic_logging()

                # Collect logs (required for cluster sync)
                capture.message = "Collecting diagnostic logs..."
                await client.collect_diagnostic_logs()

                # Download the diagnostic logs (tar.gz format)
                capture.message = "Downloading capture file..."
                tar_content, tar_filename = await client.download_diagnostic_logs()

                # Create output directory for this capture
                output_dir = self.storage_root / capture_id
                output_dir.mkdir(parents=True, exist_ok=True)

                # Extract pcap files from the tar.gz archive
                import tarfile
                import gzip
                import io

                pcap_files = []
                try:
                    # Decompress gzip and extract tar
                    with gzip.GzipFile(fileobj=io.BytesIO(tar_content)) as gz:
                        with tarfile.open(fileobj=gz, mode='r:') as tf:
                            for member in tf.getmembers():
                                if member.name.endswith('.pcap') and member.isfile():
                                    # Extract pcap file
                                    pcap_data = tf.extractfile(member).read()
                                    # Use just the filename, not the full path in tar
                                    pcap_name = Path(member.name).name
                                    output_path = output_dir / f"{capture.filename}_{pcap_name}"
                                    output_path.write_bytes(pcap_data)
                                    pcap_files.append(output_path)
                                    logger.info(f"Extracted pcap: {output_path} ({len(pcap_data)} bytes)")
                except Exception as e:
                    logger.error(f"Failed to extract tar.gz: {e}")
                    # Save raw content for debugging
                    raw_path = output_dir / tar_filename
                    raw_path.write_bytes(tar_content)
                    logger.info(f"Saved raw download to {raw_path}")
                    capture.local_file_path = raw_path
                    capture.file_size_bytes = len(tar_content)

                if pcap_files:
                    # Use the largest pcap file
                    pcap_files.sort(key=lambda p: p.stat().st_size, reverse=True)
                    capture.local_file_path = pcap_files[0]
                    capture.file_size_bytes = pcap_files[0].stat().st_size
                    capture.message = f"Capture file retrieved: {pcap_files[0].name}"
                    logger.info(
                        f"Retrieved capture file: {capture.local_file_path} "
                        f"({capture.file_size_bytes} bytes)"
                    )
                elif not capture.local_file_path:
                    # No pcap files found, save the tar.gz
                    tar_path = output_dir / tar_filename
                    tar_path.write_bytes(tar_content)
                    capture.local_file_path = tar_path
                    capture.file_size_bytes = len(tar_content)
                    capture.message = "Capture complete (diagnostic archive saved)"
                    logger.warning("No pcap files found in diagnostic logs, saved tar.gz")

                # Mark as completed
                capture.status = CaptureStatus.COMPLETED
                capture.completed_at = datetime.now(timezone.utc)

                logger.info(
                    f"Capture {capture_id} completed: "
                    f"{capture.file_size_bytes or 0} bytes"
                )

        except ExpresswayAuthError as e:
            logger.error(f"Capture {capture_id} auth failed: {e}")
            capture.status = CaptureStatus.FAILED
            capture.error = f"Authentication failed: {e}"
            capture.message = "Authentication failed"

        except ExpresswayConnectionError as e:
            logger.error(f"Capture {capture_id} connection failed: {e}")
            capture.status = CaptureStatus.FAILED
            capture.error = f"Connection failed: {e}"
            capture.message = "Connection failed"

        except ExpresswayAPIError as e:
            logger.error(f"Capture {capture_id} API error: {e}")
            capture.status = CaptureStatus.FAILED
            capture.error = f"API error: {e}"
            capture.message = "API request failed"

        except asyncio.CancelledError:
            logger.info(f"Capture {capture_id} cancelled")
            capture.status = CaptureStatus.CANCELLED
            capture.message = "Capture cancelled"

        except Exception as e:
            logger.exception(f"Capture {capture_id} failed: {e}")
            capture.status = CaptureStatus.FAILED
            capture.error = str(e)
            capture.message = "Capture failed"

        finally:
            if not capture.completed_at:
                capture.completed_at = datetime.now(timezone.utc)

    async def stop_capture(self, capture_id: str) -> bool:
        """
        Stop a running capture.

        Signals the capture to stop by setting the stop event.
        The capture task will then send Ctrl+C, retrieve the file,
        and complete normally.

        Args:
            capture_id: Capture identifier

        Returns:
            True if stop was initiated, False if capture not found/not running
        """
        capture = self._captures.get(capture_id)
        if not capture:
            return False

        if capture.status != CaptureStatus.RUNNING:
            return False

        logger.info(f"Stop requested for capture {capture_id}")
        capture.status = CaptureStatus.STOPPING
        capture._stop_event.set()  # Signal the capture loop to stop
        return True


def get_capture_manager() -> CaptureManager:
    """Get the singleton CaptureManager instance"""
    return CaptureManager.get_instance()
