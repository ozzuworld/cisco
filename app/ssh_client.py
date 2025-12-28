"""AsyncSSH client for interactive CUCM CLI sessions"""

import asyncio
import logging
import re
import time
from typing import Optional
import asyncssh
from asyncssh import SSHClientConnection, SSHClientSession


logger = logging.getLogger(__name__)


class CUCMSSHClientError(Exception):
    """Base exception for CUCM SSH client errors"""
    pass


class CUCMAuthError(CUCMSSHClientError):
    """Authentication failed"""
    pass


class CUCMConnectionError(CUCMSSHClientError):
    """Connection failed (timeout, network unreachable, etc)"""
    pass


class CUCMCommandTimeoutError(CUCMSSHClientError):
    """Command execution timed out"""
    pass


class CUCMSFTPTimeoutError(CUCMSSHClientError):
    """BE-032: SFTP upload operation timed out"""
    pass


class InteractiveShellSession:
    """
    Manages an interactive SSH shell session with CUCM CLI.

    CUCM CLI is prompt-driven and requires PTY + interactive shell.
    Do NOT use exec_command() as it may hang.
    """

    def __init__(
        self,
        stdin: asyncssh.SSHWriter,
        stdout: asyncssh.SSHReader,
        stderr: asyncssh.SSHReader,
        prompt: str = "admin:"
    ):
        """
        Initialize the interactive shell session.

        Args:
            stdin: SSH stdin writer
            stdout: SSH stdout reader
            stderr: SSH stderr reader
            prompt: Expected command prompt (default: "admin:")
        """
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.prompt = prompt
        self._buffer = ""

    async def read_until_prompt(
        self,
        timeout: float = 30.0,
        min_read_duration: float = 0.5,
        request_id: Optional[str] = None
    ) -> str:
        """
        Read output until we see the command prompt.

        Uses regex to match prompt in forms: admin:\r\n, \radmin:, etc.
        Includes minimum read duration to avoid early exit before all output arrives.

        Args:
            timeout: Maximum timeout in seconds
            min_read_duration: Minimum time to read before checking for prompt (default 0.5s)
            request_id: Optional request ID for debug logging

        Returns:
            Output text before the prompt

        Raises:
            CUCMCommandTimeoutError: If timeout is exceeded
        """
        # Regex pattern to match prompt with \r variations
        # Matches: "admin:" at start of line or after \r, with optional whitespace
        # Examples: "admin:", "\radmin:", "admin:\r\n", " admin: "
        prompt_pattern = re.compile(r'(?m)(^|\r)\s*' + re.escape(self.prompt) + r'\s*$')

        start_time = time.time()
        bytes_read = 0
        iterations = 0
        prompt_found = False

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
                    # This prevents early exit before all output has arrived
                    if elapsed >= min_read_duration:
                        match = prompt_pattern.search(self._buffer)
                        if match:
                            prompt_found = True
                            # Extract output before the prompt
                            output_text = self._buffer[:match.start()]

                            # Keep anything after the prompt in buffer for next read
                            self._buffer = self._buffer[match.end():]

                            # Debug logging for tiny output (potential bug indicator)
                            if len(output_text.strip()) < 50:
                                logger.warning(
                                    f"Tiny output captured ({len(output_text)} bytes): "
                                    f"request_id={request_id or 'N/A'}, "
                                    f"prompt_seen={prompt_found}, "
                                    f"bytes_read={bytes_read}, "
                                    f"iterations={iterations}, "
                                    f"elapsed={elapsed:.2f}s, "
                                    f"output={repr(output_text[:100])}"
                                )

                            return output_text

                    # If no more data, check one last time for prompt, then return
                    if not chunk:
                        # Check for prompt one last time at EOF
                        match = prompt_pattern.search(self._buffer)
                        if match:
                            prompt_found = True
                            output_text = self._buffer[:match.start()]
                            self._buffer = self._buffer[match.end():]

                            # Debug logging for tiny output
                            if len(output_text.strip()) < 50:
                                logger.warning(
                                    f"Tiny output at EOF ({len(output_text)} bytes): "
                                    f"request_id={request_id or 'N/A'}, "
                                    f"prompt_seen={prompt_found}, "
                                    f"bytes_read={bytes_read}, "
                                    f"iterations={iterations}, "
                                    f"output={repr(output_text[:100])}"
                                )

                            return output_text
                        else:
                            # EOF without finding prompt - return what we have
                            logger.warning(
                                f"EOF before prompt: bytes_read={bytes_read}, "
                                f"iterations={iterations}, buffer_len={len(self._buffer)}"
                            )
                            output_text = self._buffer
                            self._buffer = ""
                            return output_text

        except TimeoutError:
            # Debug logging on timeout
            buffer_tail = self._buffer[-500:] if len(self._buffer) > 500 else self._buffer
            logger.error(
                f"Timeout waiting for prompt '{self.prompt}' after {timeout}s. "
                f"request_id={request_id or 'N/A'}, "
                f"prompt_seen={prompt_found}, "
                f"bytes_read={bytes_read}, "
                f"iterations={iterations}, "
                f"buffer_len={len(self._buffer)}, "
                f"Buffer tail (last 500 chars): {repr(buffer_tail)}"
            )
            raise CUCMCommandTimeoutError(
                f"Timeout waiting for prompt '{self.prompt}' after {timeout}s"
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
            timeout: Timeout in seconds

        Returns:
            Command output (excluding the prompt)

        Raises:
            CUCMCommandTimeoutError: If timeout is exceeded
        """
        logger.debug(f"Sending command: {command[:50]}...")  # Log first 50 chars only

        # Send command with newline
        self.stdin.write(command + '\n')
        await self.stdin.drain()

        # Read until we get the prompt back
        output = await self.read_until_prompt(timeout=timeout)

        return output

    def close(self):
        """Close the stdin writer"""
        self.stdin.close()


class CUCMSSHClient:
    """
    AsyncSSH client for connecting to CUCM OS Admin CLI.

    Provides interactive shell session management with proper timeout handling.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        connect_timeout: float = 30.0,
        prompt: str = "admin:"
    ):
        """
        Initialize CUCM SSH client.

        Args:
            host: CUCM hostname or IP
            port: SSH port (typically 22)
            username: OS Admin username
            password: OS Admin password (not logged)
            connect_timeout: Connection timeout in seconds
            prompt: Expected CLI prompt (default: "admin:")
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password  # Never log this
        self.connect_timeout = connect_timeout
        self.prompt = prompt
        self._connection: Optional[SSHClientConnection] = None
        self._session: Optional[InteractiveShellSession] = None

    async def connect(self) -> None:
        """
        Establish SSH connection to CUCM.

        Raises:
            CUCMAuthError: If authentication fails
            CUCMConnectionError: If connection fails
        """
        logger.info(f"Connecting to CUCM at {self.host}:{self.port} as {self.username}")

        try:
            # Connect with explicit timeouts
            self._connection = await asyncio.wait_for(
                asyncssh.connect(
                    host=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    known_hosts=None,  # Accept any host key (for lab environments)
                    # Security note: In production, you should manage known_hosts properly
                    server_host_key_algs=['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512'],
                    encryption_algs=['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', 'aes256-cbc'],
                    kex_algs=['diffie-hellman-group-exchange-sha256', 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1'],
                    login_timeout=self.connect_timeout,
                ),
                timeout=self.connect_timeout
            )

            logger.info("SSH connection established")

            # Create interactive shell session with PTY
            stdin, stdout, stderr = await self._connection.open_session(
                term_type='vt100',
                term_size=(80, 24)
            )

            self._session = InteractiveShellSession(
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                prompt=self.prompt
            )

            # PTY startup sequence: read banner for 2-4s, then send newline, then wait for prompt
            logger.debug("Reading initial banner/welcome messages for 3s...")
            try:
                # Read banner for 3 seconds (allows welcome messages to arrive)
                async with asyncio.timeout(3.0):
                    while True:
                        chunk = await stdout.read(1024)
                        if chunk:
                            self._session._buffer += chunk
                        else:
                            break  # EOF
            except asyncio.TimeoutError:
                # Expected - we just wanted to collect banner text
                pass

            logger.debug(f"Banner collected ({len(self._session._buffer)} bytes), sending newline...")
            stdin.write('\n')
            await stdin.drain()

            # Now wait for prompt with increased timeout
            logger.debug("Waiting for prompt...")
            await self._session.read_until_prompt(timeout=60.0)
            logger.info("Interactive shell session ready")

        except asyncio.TimeoutError:
            raise CUCMConnectionError(
                f"Connection timeout to {self.host}:{self.port} after {self.connect_timeout}s"
            )
        except asyncssh.PermissionDenied:
            raise CUCMAuthError(
                f"Authentication failed for user '{self.username}' on {self.host}"
            )
        except asyncssh.DisconnectError as e:
            raise CUCMConnectionError(
                f"SSH disconnect error: {str(e)}"
            )
        except OSError as e:
            # Network unreachable, connection refused, etc.
            raise CUCMConnectionError(
                f"Network error connecting to {self.host}:{self.port}: {str(e)}"
            )
        except Exception as e:
            raise CUCMConnectionError(
                f"Unexpected error connecting to {self.host}: {str(e)}"
            )

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
            CUCMSSHClientError: If not connected
            CUCMCommandTimeoutError: If command times out
        """
        if not self._session:
            raise CUCMSSHClientError("Not connected. Call connect() first.")

        logger.info(f"Executing command: {command}")
        output = await self._session.send_command(command, timeout=timeout)
        logger.debug(f"Command output length: {len(output)} bytes")

        return output

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


async def run_show_network_cluster(
    host: str,
    port: int,
    username: str,
    password: str,
    connect_timeout: float = 30.0,
    command_timeout: float = 120.0
) -> str:
    """
    High-level function to run 'show network cluster' on CUCM.

    Args:
        host: CUCM hostname or IP
        port: SSH port
        username: OS Admin username
        password: OS Admin password
        connect_timeout: Connection timeout in seconds
        command_timeout: Command execution timeout in seconds

    Returns:
        Raw command output

    Raises:
        CUCMAuthError: Authentication failed
        CUCMConnectionError: Connection failed
        CUCMCommandTimeoutError: Command timed out
    """
    async with CUCMSSHClient(
        host=host,
        port=port,
        username=username,
        password=password,
        connect_timeout=connect_timeout
    ) as client:
        output = await client.execute_command(
            "show network cluster",
            timeout=command_timeout
        )
        return output
