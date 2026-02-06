"""Expressway REST API client for diagnostic logging with packet capture"""

import asyncio
import logging
import zipfile
import io
from typing import Optional, Dict, Any
from pathlib import Path

import httpx


logger = logging.getLogger(__name__)


class ExpresswayError(Exception):
    """Base exception for Expressway client errors"""
    pass


class ExpresswayAuthError(ExpresswayError):
    """Authentication failed"""
    pass


class ExpresswayConnectionError(ExpresswayError):
    """Connection to Expressway failed"""
    pass


class ExpresswayAPIError(ExpresswayError):
    """API request failed"""
    pass


class ExpresswayClient:
    """
    Async client for Expressway diagnostic logging REST API.

    Uses the /api/v1/provisioning/common/diagnosticlogging endpoint
    to start/stop packet captures with tcpdump.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        verify_ssl: bool = False,
        timeout: float = 30.0,
    ):
        """
        Initialize Expressway client.

        Args:
            host: Expressway hostname or IP
            username: Admin username
            password: Admin password
            port: HTTPS port (default 443)
            verify_ssl: Verify SSL certificates (default False for self-signed)
            timeout: Request timeout in seconds
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.base_url = f"https://{host}:{port}"
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    async def connect(self) -> None:
        """Create HTTP client connection"""
        logger.info(f"Connecting to Expressway at {self.host}:{self.port}")

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            auth=(self.username, self.password),
            verify=self.verify_ssl,
            timeout=httpx.Timeout(self.timeout, connect=10.0),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-CSRF-Header": "nocheck",  # Required for Expressway X14.2+
            },
        )

        # Test connection with a simple API call
        try:
            response = await self._client.get("/api/v1/provisioning/common/cluster/peers")
            if response.status_code == 401:
                raise ExpresswayAuthError("Authentication failed - check username/password")
            elif response.status_code >= 400:
                logger.warning(f"Cluster peers API returned {response.status_code}, but connection OK")
            logger.info("Expressway connection established")
        except httpx.ConnectError as e:
            raise ExpresswayConnectionError(f"Failed to connect to Expressway: {e}")
        except httpx.TimeoutException as e:
            raise ExpresswayConnectionError(f"Connection timeout: {e}")

    async def close(self) -> None:
        """Close HTTP client connection"""
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.info("Expressway connection closed")

    async def _api_request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> httpx.Response:
        """
        Make an API request to Expressway.

        Automatically retries with POST if PUT returns 405 (Method Not Allowed),
        since some Expressway firmware versions use POST instead of PUT for the
        diagnostic logging API.

        Args:
            method: HTTP method (GET, PUT, POST, etc.)
            endpoint: API endpoint path
            json_data: JSON body data
            timeout: Optional timeout override

        Returns:
            httpx.Response object
        """
        if not self._client:
            raise ExpresswayError("Client not connected")

        request_timeout = timeout or self.timeout

        try:
            response = await self._client.request(
                method=method,
                url=endpoint,
                json=json_data,
                timeout=request_timeout,
            )

            # If PUT returns 405 (Method Not Allowed), retry with POST
            # Some Expressway versions accept POST instead of PUT
            if response.status_code == 405 and method.upper() == "PUT":
                logger.info(
                    f"Expressway returned 405 for PUT {endpoint}, retrying with POST"
                )
                response = await self._client.request(
                    method="POST",
                    url=endpoint,
                    json=json_data,
                    timeout=request_timeout,
                )

            return response
        except httpx.TimeoutException as e:
            raise ExpresswayAPIError(f"Request timeout: {e}")
        except httpx.RequestError as e:
            raise ExpresswayAPIError(f"Request failed: {e}")

    async def start_diagnostic_logging(self, tcpdump: bool = True) -> Dict[str, Any]:
        """
        Start diagnostic logging with optional tcpdump.

        Args:
            tcpdump: Enable packet capture (default True)

        Returns:
            API response data
        """
        logger.info(f"Starting diagnostic logging on {self.host} (tcpdump={tcpdump})")

        payload = {
            "Mode": "start",
            "TCPDump": "on" if tcpdump else "off",
        }

        response = await self._api_request(
            "PUT",
            "/api/v1/provisioning/common/diagnosticlogging",
            json_data=payload,
        )

        if response.status_code == 200:
            logger.info("Diagnostic logging started successfully")
            return response.json() if response.text else {}
        elif response.status_code == 400:
            error_msg = "Unknown error"
            if response.text:
                try:
                    error_msg = response.json().get("Message", response.text)
                except Exception:
                    error_msg = response.text or "Bad request"
            raise ExpresswayAPIError(f"Failed to start logging: {error_msg}")
        else:
            raise ExpresswayAPIError(f"Unexpected status {response.status_code}: {response.text}")

    async def stop_diagnostic_logging(self) -> Dict[str, Any]:
        """
        Stop diagnostic logging.

        Returns:
            API response data
        """
        logger.info(f"Stopping diagnostic logging on {self.host}")

        payload = {"Mode": "stop"}

        response = await self._api_request(
            "PUT",
            "/api/v1/provisioning/common/diagnosticlogging",
            json_data=payload,
        )

        if response.status_code == 200:
            logger.info("Diagnostic logging stopped successfully")
            return response.json() if response.text else {}
        elif response.status_code == 400:
            error_msg = "Unknown error"
            if response.text:
                try:
                    error_msg = response.json().get("Message", response.text)
                except Exception:
                    error_msg = response.text or "Bad request"
            raise ExpresswayAPIError(f"Failed to stop logging: {error_msg}")
        else:
            raise ExpresswayAPIError(f"Unexpected status {response.status_code}: {response.text}")

    async def collect_diagnostic_logs(self, timeout: float = 120.0) -> Dict[str, Any]:
        """
        Collect diagnostic logs (aggregates from cluster peers).

        This step is required before downloading logs on clustered Expressways.
        The collection runs asynchronously on the server, so we poll for completion.

        Args:
            timeout: Timeout for collection (can take a while on clusters)

        Returns:
            API response data
        """
        logger.info(f"Collecting diagnostic logs from {self.host}")

        payload = {"Mode": "collect"}

        response = await self._api_request(
            "PUT",
            "/api/v1/provisioning/common/diagnosticlogging",
            json_data=payload,
            timeout=timeout,
        )

        if response.status_code == 200:
            logger.info("Diagnostic logs collection started, waiting for completion...")
            # Collection is async - wait for it to complete
            await self._wait_for_collection_complete(timeout=timeout)
            return response.json() if response.text else {}
        elif response.status_code == 400:
            error_msg = "Unknown error"
            if response.text:
                try:
                    error_msg = response.json().get("Message", response.text)
                except Exception:
                    error_msg = response.text or "Bad request"
            raise ExpresswayAPIError(f"Failed to collect logs: {error_msg}")
        else:
            raise ExpresswayAPIError(f"Unexpected status {response.status_code}: {response.text}")

    async def _wait_for_collection_complete(
        self,
        timeout: float = 120.0,
        poll_interval: float = 3.0
    ) -> None:
        """
        Wait for log collection to complete by polling status.

        Args:
            timeout: Maximum time to wait
            poll_interval: Time between status checks
        """
        import time
        start_time = time.monotonic()

        while time.monotonic() - start_time < timeout:
            # Check if download is available by trying to get status
            try:
                response = await self._api_request(
                    "GET",
                    "/api/v1/provisioning/common/diagnosticlogging",
                    timeout=10.0,
                )

                if response.status_code == 200:
                    data = response.json() if response.text else {}
                    status = data.get("Status", "").lower()
                    logger.debug(f"Diagnostic logging status: {status}")

                    # Check if collection is complete
                    if "complete" in status or "ready" in status or "collected" in status:
                        logger.info("Log collection complete")
                        return
                    elif "collecting" in status or "progress" in status:
                        logger.debug("Collection in progress...")
                    else:
                        # Unknown status, wait a bit and assume it might be ready
                        await asyncio.sleep(poll_interval)
                        elapsed = time.monotonic() - start_time
                        if elapsed >= 10.0:  # After 10s, try download anyway
                            logger.info(f"Collection status unknown ({status}), proceeding after {elapsed:.1f}s")
                            return
            except ExpresswayAPIError as e:
                logger.debug(f"Status check failed: {e}")

            await asyncio.sleep(poll_interval)

        logger.warning(f"Collection timeout after {timeout}s, attempting download anyway")

    async def download_diagnostic_logs(self, timeout: float = 300.0) -> tuple[bytes, str]:
        """
        Download diagnostic logs as a tar.gz file.

        The Expressway returns the file directly in the response body.
        Filename is in the Content-Disposition header.

        Args:
            timeout: Download timeout (large files may take time)

        Returns:
            Tuple of (file content as bytes, filename)
        """
        logger.info(f"Downloading diagnostic logs from {self.host}")

        payload = {"Mode": "download"}

        response = await self._api_request(
            "PUT",
            "/api/v1/provisioning/common/diagnosticlogging",
            json_data=payload,
            timeout=timeout,
        )

        if response.status_code == 200:
            content_type = response.headers.get("content-type", "")
            content_length = len(response.content)

            # Get filename from Content-Disposition header
            content_disposition = response.headers.get("content-disposition", "")
            filename = "diagnostic.tar.gz"
            if "filename=" in content_disposition:
                # Parse filename from header like: attachment; filename="file.tar.gz"
                import re
                match = re.search(r'filename[*]?=["\']?([^"\';\s]+)', content_disposition)
                if match:
                    filename = match.group(1)

            logger.info(f"Downloaded {content_length} bytes, type={content_type}, filename={filename}")
            return response.content, filename
        elif response.status_code == 400:
            error_msg = "Unknown error"
            if response.text:
                try:
                    error_msg = response.json().get("Message", response.text)
                except Exception:
                    error_msg = response.text or "Bad request"
            raise ExpresswayAPIError(f"Failed to download logs: {error_msg}")
        else:
            raise ExpresswayAPIError(f"Unexpected status {response.status_code}: {response.text}")

    async def run_capture(
        self,
        duration_sec: int,
        output_dir: Path,
        filename_prefix: str = "expressway",
    ) -> Optional[Path]:
        """
        Run a complete packet capture cycle.

        1. Start diagnostic logging with tcpdump
        2. Wait for duration
        3. Stop diagnostic logging
        4. Collect logs
        5. Download and extract pcap files

        Args:
            duration_sec: Capture duration in seconds
            output_dir: Directory to save pcap files
            filename_prefix: Prefix for output files

        Returns:
            Path to the extracted pcap file, or None if not found
        """
        logger.info(f"Starting Expressway capture for {duration_sec}s")

        # Start capture
        await self.start_diagnostic_logging(tcpdump=True)

        # Wait for duration
        logger.info(f"Capturing for {duration_sec} seconds...")
        await asyncio.sleep(duration_sec)

        # Stop capture
        await self.stop_diagnostic_logging()

        # Collect logs (required for cluster sync)
        await self.collect_diagnostic_logs()

        # Download the zip file
        zip_content = await self.download_diagnostic_logs()

        # Extract pcap files from the zip
        output_dir.mkdir(parents=True, exist_ok=True)
        pcap_files = []

        try:
            with zipfile.ZipFile(io.BytesIO(zip_content)) as zf:
                for name in zf.namelist():
                    if name.endswith('.pcap'):
                        # Extract pcap file
                        pcap_data = zf.read(name)
                        # Use just the filename, not the full path in zip
                        pcap_name = Path(name).name
                        output_path = output_dir / f"{filename_prefix}_{pcap_name}"
                        output_path.write_bytes(pcap_data)
                        pcap_files.append(output_path)
                        logger.info(f"Extracted pcap: {output_path} ({len(pcap_data)} bytes)")
        except zipfile.BadZipFile as e:
            logger.error(f"Invalid zip file: {e}")
            # Save raw content for debugging
            raw_path = output_dir / f"{filename_prefix}_diagnostic.zip"
            raw_path.write_bytes(zip_content)
            logger.info(f"Saved raw download to {raw_path}")
            return None

        if pcap_files:
            # Return the first (or largest) pcap file
            pcap_files.sort(key=lambda p: p.stat().st_size, reverse=True)
            return pcap_files[0]
        else:
            logger.warning("No pcap files found in diagnostic logs")
            # Save the zip for manual inspection
            zip_path = output_dir / f"{filename_prefix}_diagnostic.zip"
            zip_path.write_bytes(zip_content)
            logger.info(f"Saved diagnostic zip to {zip_path}")
            return zip_path
