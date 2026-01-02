"""Packet capture service for CUCM"""

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
        self.device_type = CaptureDeviceType.CUCM
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
        Execute a packet capture.

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
            f"Starting capture {capture_id} on {request.host} "
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
            # The SFTP server chroots to storage/received, so files land in artifacts_dir
            sftp_upload_dir = settings.artifacts_dir / capture.capture_id
            try:
                sftp_upload_dir.mkdir(parents=True, exist_ok=True)
                sftp_upload_dir.chmod(0o777)  # World-writable for SFTP user access
                logger.info(f"Created SFTP upload directory: {sftp_upload_dir}")
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

            # Check if file was transferred to SFTP upload directory
            sftp_received_file = sftp_upload_dir / capture_file

            if sftp_received_file.exists():
                capture.local_file_path = sftp_received_file
                capture.file_size_bytes = sftp_received_file.stat().st_size
                capture.message = f"Capture file retrieved: {capture_file}"
                logger.info(f"Retrieved capture file: {sftp_received_file}")
            else:
                # File not found
                logger.warning(f"Capture file not found at {sftp_received_file}")
                capture.message = f"Capture complete, file retrieval pending"

        except (asyncio.TimeoutError, CUCMCommandTimeoutError) as e:
            logger.warning(f"Timeout retrieving capture file for {capture.capture_id}: {e}")
            capture.message = "Capture complete, file retrieval timed out"

        except Exception as e:
            logger.warning(f"Failed to retrieve capture file: {e}")
            capture.message = f"Capture complete, file retrieval failed: {e}"

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
