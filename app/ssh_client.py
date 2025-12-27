"""AsyncSSH client for interactive CUCM CLI sessions"""

import asyncio
import logging
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

    async def read_until_prompt(self, timeout: float = 30.0) -> str:
        """
        Read output until we see the command prompt.

        Args:
            timeout: Timeout in seconds

        Returns:
            Output text before the prompt

        Raises:
            CUCMCommandTimeoutError: If timeout is exceeded
        """
        output = []
        try:
            async with asyncio.timeout(timeout):
                while True:
                    # Read chunk
                    chunk = await self.stdout.read(1024)
                    if not chunk:
                        # EOF
                        break

                    self._buffer += chunk

                    # Check if we've received the prompt (BE-010: handle \r variations)
                    # CUCM may send prompts like "\radmin:" or "admin:\r\n"
                    # Normalize by checking if prompt appears after stripping \r
                    normalized_buffer = self._buffer.replace('\r', '')
                    if self.prompt in normalized_buffer:
                        # Split at prompt in the normalized buffer
                        before_prompt, _, after_prompt = normalized_buffer.partition(self.prompt)
                        output.append(before_prompt)

                        # Update actual buffer to remove everything up to and including the prompt
                        # Find the position of prompt in the normalized buffer
                        prompt_pos = len(before_prompt)
                        # Now find corresponding position in original buffer
                        # This is tricky with \r, so let's just clear the buffer for simplicity
                        # since we've consumed up to the prompt
                        self._buffer = ""  # Clear buffer after finding prompt
                        break
                    else:
                        # Keep reading
                        continue

        except TimeoutError:
            # BE-010: Add debug tail logging on timeout
            buffer_tail = self._buffer[-500:] if len(self._buffer) > 500 else self._buffer
            logger.error(
                f"Timeout waiting for prompt '{self.prompt}' after {timeout}s. "
                f"Buffer tail (last 500 chars): {repr(buffer_tail)}"
            )
            raise CUCMCommandTimeoutError(
                f"Timeout waiting for prompt '{self.prompt}' after {timeout}s"
            )

        return ''.join(output)

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

            # BE-010: Send newline after opening PTY to trigger prompt
            logger.debug("Sending newline to trigger prompt...")
            stdin.write('\n')
            await stdin.drain()

            # BE-010: Read initial banner/prompt with increased timeout (60s)
            logger.debug("Reading initial banner...")
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
