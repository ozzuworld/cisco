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
from app.profiles import get_profile_catalog, CubeProfile, ExpresswayProfile


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
        self.profile_name: Optional[str] = request.profile
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
            profile=self.profile_name,
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

        # Validate profile if specified
        if request.profile:
            catalog = get_profile_catalog()

            if request.device_type == LogDeviceType.CUBE:
                if not catalog.cube_profile_exists(request.profile):
                    available = [p.name for p in catalog.list_cube_profiles()]
                    raise ValueError(
                        f"Profile not found: {request.profile}. "
                        f"Available CUBE profiles: {', '.join(available) or 'none'}"
                    )
            elif request.device_type == LogDeviceType.EXPRESSWAY:
                if not catalog.expressway_profile_exists(request.profile):
                    available = [p.name for p in catalog.list_expressway_profiles()]
                    raise ValueError(
                        f"Profile not found: {request.profile}. "
                        f"Available Expressway profiles: {', '.join(available) or 'none'}"
                    )

        collection = LogCollection(
            collection_id=collection_id,
            request=request,
        )

        self._collections[collection_id] = collection
        logger.info(
            f"Created log collection {collection_id} for {request.device_type} "
            f"at {request.host} (profile={request.profile or 'default'})"
        )

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

        # Load profile if specified
        cube_profile: Optional[CubeProfile] = None
        if request.profile:
            catalog = get_profile_catalog()
            cube_profile = catalog.get_cube_profile(request.profile)
            if cube_profile:
                collection.profile_name = cube_profile.name
                logger.info(f"Using CUBE profile: {cube_profile.name}")

        settings = get_settings()

        try:
            async with CSRSSHClient(
                host=request.host,
                port=request.port,
                username=request.username,
                password=request.password,
                connect_timeout=float(request.connect_timeout_sec),
            ) as client:
                # Determine collection method from profile or request
                include_debug = request.include_debug
                if cube_profile:
                    include_debug = cube_profile.include_debug

                if include_debug:
                    collection.method = LogCollectionMethod.DEBUG_CCSIP
                    await self._collect_cube_debug(client, collection, cube_profile)
                else:
                    collection.method = LogCollectionMethod.VOIP_TRACE
                    await self._collect_cube_voip_trace(client, collection, cube_profile)

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
        collection: LogCollection,
        profile: Optional[CubeProfile] = None
    ) -> None:
        """
        Collect VoIP Trace logs from CUBE.

        Uses 'show voip trace all' command which is available on IOS-XE 17.3.2+.
        This is the recommended method as it has minimal CPU impact.
        """
        collection.message = "Collecting VoIP Trace logs..."
        logger.info(f"Collecting VoIP Trace from {collection.request.host}")

        # Get commands from profile or use default
        commands = ["show voip trace all"]
        if profile and profile.commands:
            commands = profile.commands

        # Execute all commands and combine output
        all_output = []
        for cmd in commands:
            logger.info(f"Executing: {cmd}")
            output = await client.execute_command(cmd, timeout=120.0)
            if output:
                all_output.append(f"=== {cmd} ===\n{output}\n")

        combined_output = "\n".join(all_output) if all_output else ""

        if not combined_output or "No traces" in combined_output:
            logger.warning("No VoIP trace data available")
            collection.message = "No trace data available"
            # Still save empty file for consistency
            combined_output = "# No VoIP trace data available\n"

        # Save output to file
        output_dir = self.storage_root / collection.collection_id
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        profile_suffix = f"_{profile.name}" if profile else ""
        output_file = output_dir / f"voip_trace{profile_suffix}_{timestamp}.txt"
        output_file.write_text(combined_output)

        collection.local_file_path = output_file
        collection.file_size_bytes = output_file.stat().st_size
        collection.message = f"Collected VoIP Trace: {collection.file_size_bytes} bytes"

        logger.info(f"Saved VoIP Trace to {output_file} ({collection.file_size_bytes} bytes)")

    async def _collect_cube_debug(
        self,
        client: CSRSSHClient,
        collection: LogCollection,
        profile: Optional[CubeProfile] = None
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

        # Get duration from profile or request
        duration_sec = request.duration_sec
        if profile and profile.duration_sec:
            duration_sec = profile.duration_sec

        # Get debug commands from profile or use defaults
        debug_commands = ["debug ccsip messages", "debug voip ccapi inout"]
        if profile and profile.commands:
            # Filter to only debug commands
            debug_commands = [cmd for cmd in profile.commands if cmd.startswith("debug ")]

        try:
            collection.message = "Enabling debug logging..."
            logger.info(f"Enabling debug on {request.host} for {duration_sec}s")

            # Clear logging buffer first
            await client.execute_command("clear logging", timeout=10.0)

            # Enable debugs
            for cmd in debug_commands:
                logger.info(f"Enabling: {cmd}")
                await client.execute_command(cmd, timeout=10.0)

            collection.message = f"Capturing debug logs for {duration_sec}s..."

            # Wait for duration
            await asyncio.sleep(duration_sec)

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
        profile_suffix = f"_{profile.name}" if profile else ""
        output_file = output_dir / f"debug_log{profile_suffix}_{timestamp}.txt"
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

        # Load profile if specified
        exp_profile: Optional[ExpresswayProfile] = None
        if request.profile:
            catalog = get_profile_catalog()
            exp_profile = catalog.get_expressway_profile(request.profile)
            if exp_profile:
                collection.profile_name = exp_profile.name
                logger.info(f"Using Expressway profile: {exp_profile.name}")

        # Get tcpdump setting from profile (default: False for faster collection)
        enable_tcpdump = False
        if exp_profile:
            enable_tcpdump = exp_profile.tcpdump

        try:
            async with ExpresswayClient(
                host=request.host,
                username=request.username,
                password=request.password,
                port=request.port or 443,
            ) as client:
                # Start diagnostic logging
                collection.message = "Starting diagnostic logging..."
                await client.start_diagnostic_logging(tcpdump=enable_tcpdump)

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
