"""AsyncSSH client for CSR1000v / IOS-XE CLI sessions"""

import asyncio
import logging
import re
import time
from typing import Optional
import asyncssh
from asyncssh import SSHClientConnection


logger = logging.getLogger(__name__)


class CSRSSHClientError(Exception):
    """Base exception for CSR SSH client errors"""
    pass


class CSRAuthError(CSRSSHClientError):
    """Authentication failed"""
    pass


class CSRConnectionError(CSRSSHClientError):
    """Connection failed (timeout, network unreachable, etc)"""
    pass


class CSRCommandTimeoutError(CSRSSHClientError):
    """Command execution timed out"""
    pass


class IOSXEShellSession:
    """
    Manages an interactive SSH shell session with IOS-XE CLI.

    IOS-XE uses privilege exec mode with prompts like "Router#" or "hostname#".
    """

    def __init__(
        self,
        stdin: asyncssh.SSHWriter,
        stdout: asyncssh.SSHReader,
        stderr: asyncssh.SSHReader,
        prompt_pattern: str = r"[\w\-]+#\s*$"
    ):
        """
        Initialize the interactive shell session.

        Args:
            stdin: SSH stdin writer
            stdout: SSH stdout reader
            stderr: SSH stderr reader
            prompt_pattern: Regex pattern to match the CLI prompt (default: hostname#)
        """
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.prompt_pattern = re.compile(prompt_pattern)
        self._buffer = ""

    async def read_until_prompt(
        self,
        timeout: float = 30.0,
        min_read_duration: float = 0.5,
        request_id: Optional[str] = None
    ) -> str:
        """
        Read output until we see the command prompt.

        Args:
            timeout: Maximum timeout in seconds
            min_read_duration: Minimum time to read before checking for prompt
            request_id: Optional request ID for debug logging

        Returns:
            Output text before the prompt

        Raises:
            CSRCommandTimeoutError: If timeout is exceeded
        """
        start_time = time.time()
        bytes_read = 0
        iterations = 0

        try:
            async with asyncio.timeout(timeout):
                while True:
                    iterations += 1

                    # Read chunk
                    chunk = await self.stdout.read(1024)
                    if chunk:
                        self._buffer += chunk
                        bytes_read += len(chunk)

                    elapsed = time.time() - start_time

                    # Check for prompt only after minimum read duration
                    if elapsed >= min_read_duration:
                        match = self.prompt_pattern.search(self._buffer)
                        if match:
                            # Extract output before the prompt
                            output_text = self._buffer[:match.start()]
                            self._buffer = self._buffer[match.end():]
                            return output_text

                    # If no more data, check one last time
                    if not chunk:
                        match = self.prompt_pattern.search(self._buffer)
                        if match:
                            output_text = self._buffer[:match.start()]
                            self._buffer = self._buffer[match.end():]
                            return output_text
                        else:
                            # EOF without prompt
                            logger.warning(
                                f"EOF before prompt: bytes_read={bytes_read}, "
                                f"buffer_len={len(self._buffer)}"
                            )
                            output_text = self._buffer
                            self._buffer = ""
                            return output_text

        except TimeoutError:
            # Check buffer one last time
            match = self.prompt_pattern.search(self._buffer)
            if match:
                output_text = self._buffer[:match.start()]
                self._buffer = self._buffer[match.end():]
                return output_text

            buffer_tail = self._buffer[-500:] if len(self._buffer) > 500 else self._buffer
            logger.error(
                f"Timeout waiting for IOS-XE prompt after {timeout}s. "
                f"request_id={request_id or 'N/A'}, "
                f"bytes_read={bytes_read}, "
                f"buffer_tail={repr(buffer_tail)}"
            )
            raise CSRCommandTimeoutError(
                f"Timeout waiting for prompt after {timeout}s"
            )

    async def send_command(
        self,
        command: str,
        timeout: float = 120.0
    ) -> str:
        """
        Send a command and read the response until prompt returns.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            Command output

        Raises:
            CSRCommandTimeoutError: If command times out
        """
        logger.debug(f"Sending command: {command[:50]}...")

        # Send command with newline
        self.stdin.write(command + '\n')
        await self.stdin.drain()

        # Read until we get the prompt back
        output = await self.read_until_prompt(timeout=timeout)

        return output

    async def send_command_no_wait(self, command: str) -> None:
        """
        Send a command without waiting for response.

        Args:
            command: Command to execute
        """
        logger.debug(f"Sending command (no wait): {command[:50]}...")
        self.stdin.write(command + '\n')
        await self.stdin.drain()

    def close(self):
        """Close the stdin writer"""
        self.stdin.close()


class CSRSSHClient:
    """
    AsyncSSH client for connecting to CSR1000v / IOS-XE CLI.

    Provides interactive shell session management for IOS-XE devices.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        connect_timeout: float = 30.0,
        prompt_pattern: str = r"[\w\-]+#\s*$"
    ):
        """
        Initialize CSR SSH client.

        Args:
            host: CSR hostname or IP
            port: SSH port (typically 22)
            username: CLI username
            password: CLI password (not logged)
            connect_timeout: Connection timeout in seconds
            prompt_pattern: Regex for CLI prompt (default: hostname#)
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password  # Never log this
        self.connect_timeout = connect_timeout
        self.prompt_pattern = prompt_pattern
        self._connection: Optional[SSHClientConnection] = None
        self._session: Optional[IOSXEShellSession] = None

    async def connect(self) -> None:
        """
        Establish SSH connection to CSR1000v.

        Raises:
            CSRAuthError: If authentication fails
            CSRConnectionError: If connection fails
        """
        logger.info(f"Connecting to CSR at {self.host}:{self.port} as {self.username}")

        try:
            # Connect with explicit timeouts
            self._connection = await asyncio.wait_for(
                asyncssh.connect(
                    host=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    known_hosts=None,  # Accept any host key
                    # IOS-XE may need legacy algorithms
                    kex_algs=['diffie-hellman-group-exchange-sha256',
                              'diffie-hellman-group14-sha1',
                              'diffie-hellman-group1-sha1'],
                    encryption_algs=['aes128-ctr', 'aes256-ctr', 'aes128-cbc', '3des-cbc'],
                    server_host_key_algs=['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512'],
                ),
                timeout=self.connect_timeout
            )
            logger.info("SSH connection established")

            # Start interactive shell with PTY
            stdin, stdout, stderr = await self._connection.open_session(
                term_type='xterm',
                term_size=(200, 50),
                encoding=None,  # Binary mode
            )

            self._session = IOSXEShellSession(
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                prompt_pattern=self.prompt_pattern
            )

            # Wait for initial prompt
            await self._session.read_until_prompt(timeout=30.0)
            logger.info("Interactive shell session ready")

            # Disable terminal paging
            await self._session.send_command("terminal length 0", timeout=10.0)
            logger.debug("Disabled terminal paging")

        except asyncssh.PermissionDenied as e:
            logger.error(f"Authentication failed for {self.username}@{self.host}")
            raise CSRAuthError(f"Authentication failed: {e}")

        except asyncssh.DisconnectError as e:
            logger.error(f"Connection disconnected: {e}")
            raise CSRConnectionError(f"Connection disconnected: {e}")

        except asyncio.TimeoutError:
            logger.error(f"Connection timeout to {self.host}:{self.port}")
            raise CSRConnectionError(
                f"Connection timeout after {self.connect_timeout}s"
            )

        except OSError as e:
            logger.error(f"Connection failed to {self.host}:{self.port}: {e}")
            raise CSRConnectionError(f"Connection failed: {e}")

        except Exception as e:
            logger.exception(f"Unexpected error connecting to {self.host}")
            raise CSRConnectionError(f"Connection failed: {e}")

    async def execute_command(
        self,
        command: str,
        timeout: float = 120.0
    ) -> str:
        """
        Execute a command in the interactive shell.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            Command output

        Raises:
            CSRSSHClientError: If not connected
            CSRCommandTimeoutError: If command times out
        """
        if not self._session:
            raise CSRSSHClientError("Not connected. Call connect() first.")

        logger.info(f"Executing command: {command}")
        output = await self._session.send_command(command, timeout=timeout)
        logger.debug(f"Command output length: {len(output)} bytes")

        return output

    async def send_command_no_wait(self, command: str) -> None:
        """
        Send a command without waiting for response.

        Args:
            command: Command to execute
        """
        if not self._session:
            raise CSRSSHClientError("Not connected. Call connect() first.")

        logger.info(f"Executing command (no wait): {command}")
        await self._session.send_command_no_wait(command)

    async def disconnect(self) -> None:
        """Close the SSH connection gracefully"""
        if self._session:
            logger.debug("Closing shell session")
            self._session.close()
            self._session = None

        if self._connection:
            logger.info("Closing SSH connection")
            self._connection.close()
            await self._connection.wait_closed()
            self._connection = None

    async def __aenter__(self):
        """Context manager entry"""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        await self.disconnect()
        return False


# IOS-XE Embedded Packet Capture (EPC) command builders

def build_epc_capture_config(
    capture_name: str,
    interface: str,
    buffer_size_mb: int = 10,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
) -> list[str]:
    """
    Build IOS-XE EPC configuration commands.

    Args:
        capture_name: Name for the capture point
        interface: Interface to capture on (e.g., GigabitEthernet1)
        buffer_size_mb: Capture buffer size in MB
        src_ip: Optional source IP filter
        dst_ip: Optional destination IP filter
        port: Optional port filter
        protocol: Optional protocol filter (tcp, udp, icmp)

    Returns:
        List of configuration commands
    """
    commands = []

    # Remove any existing capture with same name
    commands.append(f"no monitor capture {capture_name}")

    # Create capture point on interface
    commands.append(f"monitor capture {capture_name} interface {interface} both")

    # Set buffer size
    commands.append(f"monitor capture {capture_name} buffer size {buffer_size_mb}")

    # Build match filter
    if src_ip or dst_ip or port or protocol:
        # Build ACL-style match
        proto = protocol or "ip"
        src = f"host {src_ip}" if src_ip else "any"
        dst = f"host {dst_ip}" if dst_ip else "any"

        if port:
            # For TCP/UDP with port
            if proto in ("tcp", "udp"):
                commands.append(
                    f"monitor capture {capture_name} match ipv4 protocol {proto} "
                    f"{src} {dst} eq {port}"
                )
            else:
                commands.append(
                    f"monitor capture {capture_name} match ipv4 {src} {dst}"
                )
        else:
            if proto == "ip":
                commands.append(
                    f"monitor capture {capture_name} match ipv4 {src} {dst}"
                )
            else:
                commands.append(
                    f"monitor capture {capture_name} match ipv4 protocol {proto} {src} {dst}"
                )
    else:
        # Match all IPv4 traffic
        commands.append(f"monitor capture {capture_name} match ipv4 any any")

    return commands


def build_epc_start_command(capture_name: str) -> str:
    """Build command to start capture"""
    return f"monitor capture {capture_name} start"


def build_epc_stop_command(capture_name: str) -> str:
    """Build command to stop capture"""
    return f"monitor capture {capture_name} stop"


def build_epc_export_command(
    capture_name: str,
    export_url: str
) -> str:
    """
    Build command to export capture to file.

    Args:
        capture_name: Name of the capture point
        export_url: Destination URL (e.g., flash:capture.pcap, scp://user@host/path)

    Returns:
        Export command
    """
    return f"monitor capture {capture_name} export {export_url}"


def build_epc_clear_command(capture_name: str) -> str:
    """Build command to clear/delete capture point"""
    return f"no monitor capture {capture_name}"


def parse_epc_status(output: str) -> dict:
    """
    Parse output of 'show monitor capture <name>' command.

    Args:
        output: Raw command output

    Returns:
        Dict with parsed status info
    """
    status = {
        "state": None,
        "buffer_size": None,
        "packets": None,
        "bytes": None,
    }

    # Parse status
    state_match = re.search(r'Status\s*:\s*(\w+)', output, re.IGNORECASE)
    if state_match:
        status["state"] = state_match.group(1).lower()

    # Parse buffer size
    buffer_match = re.search(r'Buffer Size\s*:\s*(\d+)', output, re.IGNORECASE)
    if buffer_match:
        status["buffer_size"] = int(buffer_match.group(1))

    # Parse packet count
    packets_match = re.search(r'Packets\s*:\s*(\d+)', output, re.IGNORECASE)
    if packets_match:
        status["packets"] = int(packets_match.group(1))

    # Parse bytes
    bytes_match = re.search(r'Bytes\s*:\s*(\d+)', output, re.IGNORECASE)
    if bytes_match:
        status["bytes"] = int(bytes_match.group(1))

    return status
