"""Packet capture service for CUCM and CSR1000v"""

import asyncio
import logging
import uuid
import re
from datetime import datetime, timezone
from typing import Dict, Optional, List
from pathlib import Path

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
from app.config import get_settings
from app.prompt_responder import PromptResponder


logger = logging.getLogger(__name__)


# SFTP prompt timeout for file retrieval
SFTP_PROMPT_TIMEOUT = 120.0


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

                # Send Ctrl+C to stop the capture
                capture.message = "Stopping capture..."
                await client.send_interrupt()

                # Wait a moment for CUCM to process the interrupt
                await asyncio.sleep(1.0)

                # Read the output until we get the prompt back
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
                    output = ""

                # Check for cancellation before file retrieval
                if capture._cancelled:
                    capture.status = CaptureStatus.CANCELLED
                    capture.message = "Capture cancelled"
                    capture.completed_at = datetime.now(timezone.utc)
                    return

                # Give CUCM a moment to finish writing the capture file
                await asyncio.sleep(2.0)

                # Retrieve the capture file
                capture.message = "Retrieving capture file..."
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

            # Set up prompt responder for SFTP transfer
            responder = PromptResponder(
                sftp_host=settings.sftp_host,
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
                await asyncio.wait_for(
                    responder.respond_to_prompts(shell.stdin, shell.stdout),
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

        # Generate a unique capture name for EPC
        capture_name = f"CAP_{capture_id[:8]}"
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
                    logger.debug(f"EPC config: {cmd}")
                    output = await client.execute_command(cmd, timeout=30.0)
                    logger.debug(f"Output: {output[:100] if output else 'empty'}")

                # Start the capture
                capture.message = "Capturing packets..."
                start_cmd = build_epc_start_command(capture_name)
                logger.info(f"Starting EPC: {start_cmd}")
                await client.execute_command(start_cmd, timeout=30.0)

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
                await client.execute_command(stop_cmd, timeout=30.0)

                # Check capture status
                status_cmd = f"show monitor capture {capture_name}"
                status_output = await client.execute_command(status_cmd, timeout=30.0)
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

                # Create local directory for capture (where SCP will put the file)
                sftp_upload_dir = settings.artifacts_dir / capture.capture_id
                sftp_upload_dir.mkdir(parents=True, exist_ok=True)
                sftp_upload_dir.chmod(0o777)

                # Build SCP path relative to SCP user's home/chroot
                # The SCP user is chrooted with 'received/' mapped to artifacts_dir
                sftp_base = settings.sftp_remote_base_dir or ""
                if sftp_base:
                    scp_remote_path = f"{sftp_base}/{capture.capture_id}/{pcap_filename}"
                else:
                    scp_remote_path = f"{capture.capture_id}/{pcap_filename}"

                # Build SCP URL: scp://user:pass@host/path/file.pcap
                scp_url = (
                    f"scp://{settings.sftp_username}:{settings.sftp_password}"
                    f"@{settings.sftp_host}/{scp_remote_path}"
                )

                export_cmd = build_epc_export_command(capture_name, scp_url)
                logger.info(f"Exporting capture to SCP")
                try:
                    output = await client.execute_command(export_cmd, timeout=120.0)
                    logger.debug(f"Export output: {output[:200] if output else 'empty'}")
                except CSRCommandTimeoutError:
                    logger.warning("Export command timed out, file may still be transferring")

                # Clean up capture point
                clear_cmd = build_epc_clear_command(capture_name)
                await client.execute_command(clear_cmd, timeout=30.0)

                # Wait for file transfer to complete
                await asyncio.sleep(2.0)

                # Search for the capture file
                found_file = None
                for pcap in sftp_upload_dir.rglob(pcap_filename):
                    found_file = pcap
                    logger.info(f"Found capture file at: {found_file}")
                    break

                if found_file:
                    capture.local_file_path = found_file
                    capture.file_size_bytes = found_file.stat().st_size
                    capture.message = f"Capture file retrieved: {pcap_filename}"
                    logger.info(f"Retrieved capture file: {found_file} ({capture.file_size_bytes} bytes)")
                else:
                    logger.warning(f"Capture file {pcap_filename} not found in {sftp_upload_dir}")
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
