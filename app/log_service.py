"""Log collection service for CUBE and Expressway"""

import asyncio
import logging
import uuid
import tarfile
import gzip
import io
from datetime import datetime, timezone
from typing import Dict, Optional, List
from pathlib import Path
from urllib.parse import quote as url_quote

from app.models import (
    StartLogCollectionRequest,
    LogCollectionInfo,
    LogCollectionStatus,
    LogDeviceType,
    LogCollectionMethod,
)
from app.csr_client import (
    CSRSSHClient,
    CSRAuthError,
    CSRConnectionError,
    CSRCommandTimeoutError,
    CSRSSHClientError,
)
from app.expressway_client import (
    ExpresswayClient,
    ExpresswayAuthError,
    ExpresswayConnectionError,
    ExpresswayAPIError,
)
from app.config import get_settings


logger = logging.getLogger(__name__)


class LogCollection:
    """Represents a log collection operation"""

    def __init__(
        self,
        collection_id: str,
        request: StartLogCollectionRequest,
    ):
        self.collection_id = collection_id
        self.request = request
        self.status = LogCollectionStatus.PENDING
        self.device_type = request.device_type
        self.method: Optional[LogCollectionMethod] = request.method
        self.created_at = datetime.now(timezone.utc)
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error: Optional[str] = None
        self.message: Optional[str] = None
        self.file_size_bytes: Optional[int] = None
        self.local_file_path: Optional[Path] = None
        self._task: Optional[asyncio.Task] = None

    def to_info(self) -> LogCollectionInfo:
        """Convert to LogCollectionInfo model"""
        return LogCollectionInfo(
            collection_id=self.collection_id,
            status=self.status,
            device_type=self.device_type,
            method=self.method,
            host=self.request.host,
            started_at=self.started_at,
            completed_at=self.completed_at,
            created_at=self.created_at,
            file_size_bytes=self.file_size_bytes,
            error=self.error,
            message=self.message,
        )


class LogCollectionManager:
    """Manages log collection operations"""

    _instance: Optional["LogCollectionManager"] = None

    def __init__(self):
        self._collections: Dict[str, LogCollection] = {}
        self._storage_root: Optional[Path] = None

    @classmethod
    def get_instance(cls) -> "LogCollectionManager":
        """Get singleton instance"""
        if cls._instance is None:
            cls._instance = LogCollectionManager()
        return cls._instance

    @property
    def storage_root(self) -> Path:
        """Get storage root directory"""
        if self._storage_root is None:
            settings = get_settings()
            self._storage_root = Path(settings.storage_root) / "logs"
            self._storage_root.mkdir(parents=True, exist_ok=True)
        return self._storage_root

    def create_collection(self, request: StartLogCollectionRequest) -> LogCollection:
        """Create a new log collection operation"""
        collection_id = str(uuid.uuid4())

        collection = LogCollection(
            collection_id=collection_id,
            request=request,
        )

        self._collections[collection_id] = collection
        logger.info(f"Created log collection {collection_id} for {request.device_type} at {request.host}")

        return collection

    def get_collection(self, collection_id: str) -> Optional[LogCollection]:
        """Get a collection by ID"""
        return self._collections.get(collection_id)

    def list_collections(self, limit: int = 50) -> List[LogCollection]:
        """List recent collections"""
        collections = sorted(
            self._collections.values(),
            key=lambda c: c.created_at,
            reverse=True
        )
        return collections[:limit]

    def delete_collection(self, collection_id: str) -> bool:
        """Delete a collection and its files"""
        collection = self._collections.get(collection_id)
        if not collection:
            return False

        # Delete local file if exists
        if collection.local_file_path and collection.local_file_path.exists():
            try:
                collection.local_file_path.unlink()
                logger.info(f"Deleted log file: {collection.local_file_path}")
            except Exception as e:
                logger.warning(f"Failed to delete log file: {e}")

        del self._collections[collection_id]
        logger.info(f"Deleted log collection {collection_id}")
        return True

    async def execute_collection(self, collection_id: str) -> None:
        """Execute log collection - routes to appropriate method based on device type"""
        collection = self._collections.get(collection_id)
        if not collection:
            logger.error(f"Collection {collection_id} not found")
            return

        if collection.device_type == LogDeviceType.CUBE:
            await self._execute_cube_collection(collection_id)
        elif collection.device_type == LogDeviceType.EXPRESSWAY:
            await self._execute_expressway_collection(collection_id)
        else:
            logger.error(f"Unknown device type: {collection.device_type}")
            collection.status = LogCollectionStatus.FAILED
            collection.error = f"Unknown device type: {collection.device_type}"

    async def _execute_cube_collection(self, collection_id: str) -> None:
        """
        Execute log collection on CUBE using VoIP Trace or Debug.

        VoIP Trace (IOS-XE 17.3.2+): Uses 'show voip trace all'
        Debug: Enables debug ccsip messages, waits, disables, collects 'show log'

        Args:
            collection_id: Collection identifier
        """
        collection = self._collections.get(collection_id)
        if not collection:
            logger.error(f"Collection {collection_id} not found")
            return

        request = collection.request
        collection.status = LogCollectionStatus.RUNNING
        collection.started_at = datetime.now(timezone.utc)
        collection.message = "Connecting to CUBE..."

        logger.info(f"Starting CUBE log collection {collection_id} on {request.host}")

        settings = get_settings()

        try:
            async with CSRSSHClient(
                host=request.host,
                port=request.port,
                username=request.username,
                password=request.password,
                connect_timeout=float(request.connect_timeout_sec),
            ) as client:
                # Determine collection method
                if request.include_debug:
                    collection.method = LogCollectionMethod.DEBUG_CCSIP
                    await self._collect_cube_debug(client, collection)
                else:
                    collection.method = LogCollectionMethod.VOIP_TRACE
                    await self._collect_cube_voip_trace(client, collection)

                # Mark as completed
                collection.status = LogCollectionStatus.COMPLETED
                collection.completed_at = datetime.now(timezone.utc)

                logger.info(
                    f"Log collection {collection_id} completed: "
                    f"{collection.file_size_bytes or 0} bytes"
                )

        except CSRAuthError as e:
            logger.error(f"Collection {collection_id} auth failed: {e}")
            collection.status = LogCollectionStatus.FAILED
            collection.error = f"Authentication failed: {e}"
            collection.message = "Authentication failed"

        except CSRConnectionError as e:
            logger.error(f"Collection {collection_id} connection failed: {e}")
            collection.status = LogCollectionStatus.FAILED
            collection.error = f"Connection failed: {e}"
            collection.message = "Connection failed"

        except CSRCommandTimeoutError as e:
            logger.error(f"Collection {collection_id} command timeout: {e}")
            collection.status = LogCollectionStatus.FAILED
            collection.error = f"Command timeout: {e}"
            collection.message = "Command timeout"

        except Exception as e:
            logger.exception(f"Collection {collection_id} failed: {e}")
            collection.status = LogCollectionStatus.FAILED
            collection.error = str(e)
            collection.message = "Collection failed"

        finally:
            if not collection.completed_at:
                collection.completed_at = datetime.now(timezone.utc)

    async def _collect_cube_voip_trace(
        self,
        client: CSRSSHClient,
        collection: LogCollection
    ) -> None:
        """
        Collect VoIP Trace logs from CUBE.

        Uses 'show voip trace all' command which is available on IOS-XE 17.3.2+.
        This is the recommended method as it has minimal CPU impact.
        """
        collection.message = "Collecting VoIP Trace logs..."
        logger.info(f"Collecting VoIP Trace from {collection.request.host}")

        # Get VoIP trace output
        output = await client.execute_command(
            "show voip trace all",
            timeout=120.0
        )

        if not output or "No traces" in output:
            logger.warning("No VoIP trace data available")
            collection.message = "No trace data available"
            # Still save empty file for consistency
            output = "# No VoIP trace data available\n"

        # Save output to file
        output_dir = self.storage_root / collection.collection_id
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"voip_trace_{timestamp}.txt"
        output_file.write_text(output)

        collection.local_file_path = output_file
        collection.file_size_bytes = output_file.stat().st_size
        collection.message = f"Collected VoIP Trace: {collection.file_size_bytes} bytes"

        logger.info(f"Saved VoIP Trace to {output_file} ({collection.file_size_bytes} bytes)")

    async def _collect_cube_debug(
        self,
        client: CSRSSHClient,
        collection: LogCollection
    ) -> None:
        """
        Collect logs using traditional debug commands.

        WARNING: This method enables debug which can impact CPU.
        Debug is automatically disabled after collection.

        Steps:
        1. Clear logging buffer
        2. Enable debug ccsip messages
        3. Wait for specified duration
        4. Disable all debugs (CRITICAL!)
        5. Collect show log output
        """
        request = collection.request

        try:
            collection.message = "Enabling debug logging..."
            logger.info(f"Enabling debug on {request.host} for {request.duration_sec}s")

            # Clear logging buffer first
            await client.execute_command("clear logging", timeout=10.0)

            # Enable debugs
            await client.execute_command("debug ccsip messages", timeout=10.0)
            await client.execute_command("debug voip ccapi inout", timeout=10.0)

            collection.message = f"Capturing debug logs for {request.duration_sec}s..."

            # Wait for duration
            await asyncio.sleep(request.duration_sec)

        finally:
            # CRITICAL: Always disable debugs to prevent CPU impact
            collection.message = "Disabling debug logging..."
            logger.info(f"Disabling debug on {request.host}")

            try:
                await client.execute_command("undebug all", timeout=10.0)
            except Exception as e:
                logger.error(f"Failed to disable debug: {e}")
                # Try alternative command
                try:
                    await client.execute_command("no debug all", timeout=10.0)
                except Exception:
                    pass

        # Collect logs
        collection.message = "Collecting debug logs..."
        output = await client.execute_command("show log", timeout=120.0)

        if not output:
            output = "# No log data available\n"

        # Save output to file
        output_dir = self.storage_root / collection.collection_id
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"debug_log_{timestamp}.txt"
        output_file.write_text(output)

        collection.local_file_path = output_file
        collection.file_size_bytes = output_file.stat().st_size
        collection.message = f"Collected debug logs: {collection.file_size_bytes} bytes"

        logger.info(f"Saved debug logs to {output_file} ({collection.file_size_bytes} bytes)")

    async def _execute_expressway_collection(self, collection_id: str) -> None:
        """
        Execute log collection on Expressway using diagnostic logging API.

        This collects the full diagnostic log bundle including event logs,
        syslog, and optionally packet captures.

        Args:
            collection_id: Collection identifier
        """
        collection = self._collections.get(collection_id)
        if not collection:
            logger.error(f"Collection {collection_id} not found")
            return

        request = collection.request
        collection.status = LogCollectionStatus.RUNNING
        collection.started_at = datetime.now(timezone.utc)
        collection.method = LogCollectionMethod.DIAGNOSTIC
        collection.message = "Connecting to Expressway..."

        logger.info(f"Starting Expressway log collection {collection_id} on {request.host}")

        try:
            async with ExpresswayClient(
                host=request.host,
                username=request.username,
                password=request.password,
                port=request.port or 443,
            ) as client:
                # Start diagnostic logging (without tcpdump for faster collection)
                collection.message = "Starting diagnostic logging..."
                await client.start_diagnostic_logging(tcpdump=False)

                # Brief pause to capture some activity
                collection.message = "Collecting logs..."
                await asyncio.sleep(5)

                # Stop logging
                collection.message = "Stopping diagnostic logging..."
                await client.stop_diagnostic_logging()

                # Collect logs from cluster peers
                collection.message = "Collecting from cluster peers..."
                await client.collect_diagnostic_logs()

                # Download the logs
                collection.message = "Downloading diagnostic logs..."
                tar_content, tar_filename = await client.download_diagnostic_logs()

                # Save the tar.gz file
                output_dir = self.storage_root / collection_id
                output_dir.mkdir(parents=True, exist_ok=True)

                output_file = output_dir / tar_filename
                output_file.write_bytes(tar_content)

                collection.local_file_path = output_file
                collection.file_size_bytes = len(tar_content)
                collection.message = f"Downloaded diagnostic logs: {collection.file_size_bytes} bytes"

                # Mark as completed
                collection.status = LogCollectionStatus.COMPLETED
                collection.completed_at = datetime.now(timezone.utc)

                logger.info(
                    f"Log collection {collection_id} completed: "
                    f"{collection.file_size_bytes} bytes"
                )

        except ExpresswayAuthError as e:
            logger.error(f"Collection {collection_id} auth failed: {e}")
            collection.status = LogCollectionStatus.FAILED
            collection.error = f"Authentication failed: {e}"
            collection.message = "Authentication failed"

        except ExpresswayConnectionError as e:
            logger.error(f"Collection {collection_id} connection failed: {e}")
            collection.status = LogCollectionStatus.FAILED
            collection.error = f"Connection failed: {e}"
            collection.message = "Connection failed"

        except ExpresswayAPIError as e:
            logger.error(f"Collection {collection_id} API error: {e}")
            collection.status = LogCollectionStatus.FAILED
            collection.error = f"API error: {e}"
            collection.message = "API request failed"

        except Exception as e:
            logger.exception(f"Collection {collection_id} failed: {e}")
            collection.status = LogCollectionStatus.FAILED
            collection.error = str(e)
            collection.message = "Collection failed"

        finally:
            if not collection.completed_at:
                collection.completed_at = datetime.now(timezone.utc)


def get_log_collection_manager() -> LogCollectionManager:
    """Get the singleton LogCollectionManager instance"""
    return LogCollectionManager.get_instance()
