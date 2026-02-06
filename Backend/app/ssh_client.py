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
    """SFTP upload operation timed out"""
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

        deadline = start_time + timeout

        def _check_prompt():
            """Check buffer for prompt and return (output, True) or (None, False)."""
            match = prompt_pattern.search(self._buffer)
            if match:
                output_text = self._buffer[:match.start()]
                self._buffer = self._buffer[match.end():]
                return output_text, True
            return None, False

        try:
            while True:
                iterations += 1
                elapsed = time.time() - start_time

                # ── 1. Check buffer for prompt BEFORE blocking on read ──
                # After min_read_duration, the prompt may already be in the
                # buffer from a previous chunk.  Checking first avoids a
                # blocking read(1024) that would sit until the next timeout.
                if elapsed >= min_read_duration:
                    output_text, found = _check_prompt()
                    if found:
                        logger.debug(
                            f"Prompt found after {elapsed:.2f}s, "
                            f"bytes_read={bytes_read}, iterations={iterations}"
                        )
                        return output_text

                # ── 2. Read data with a short inner timeout ──
                # Use a 2-second read window so we loop back to the prompt
                # check frequently instead of blocking until the outer
                # deadline.
                remaining = deadline - time.time()
                if remaining <= 0:
                    break  # Overall timeout exceeded

                read_timeout = min(2.0, remaining)
                try:
                    chunk = await asyncio.wait_for(
                        self.stdout.read(1024), timeout=read_timeout
                    )
                except asyncio.TimeoutError:
                    # No data arrived within the read window — loop back
                    # and re-check the buffer for the prompt.
                    continue

                if chunk:
                    self._buffer += chunk
                    bytes_read += len(chunk)
                else:
                    # EOF — do a final prompt check, then return whatever we have
                    output_text, found = _check_prompt()
                    if found:
                        return output_text
                    logger.warning(
                        f"EOF before prompt: bytes_read={bytes_read}, "
                        f"iterations={iterations}, buffer_len={len(self._buffer)}"
                    )
                    output_text = self._buffer
                    self._buffer = ""
                    return output_text

        except asyncio.CancelledError:
            raise

        # ── Overall timeout: one final prompt check ──
        output_text, found = _check_prompt()
        if found:
            logger.debug(
                f"Found prompt after timeout ({timeout}s) - data was already buffered. "
                f"bytes_read={bytes_read}"
            )
            return output_text

        buffer_tail = self._buffer[-500:] if len(self._buffer) > 500 else self._buffer
        logger.error(
            f"Timeout waiting for prompt '{self.prompt}' after {timeout}s. "
            f"request_id={request_id or 'N/A'}, "
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

    async def send_command_with_confirmation(
        self,
        command: str,
        confirmation: str = "y",
        timeout: float = 60.0
    ) -> str:
        """
        Send a command that requires y/n confirmation and handle the confirmation.

        Used for commands like 'set trace enable' that ask:
        "Please answer 'y' for <yes> or 'n' for <no>:"

        Args:
            command: Command to execute
            confirmation: Response to send for confirmation (default: "y")
            timeout: Timeout in seconds

        Returns:
            Full command output including confirmation

        Raises:
            CUCMCommandTimeoutError: If timeout is exceeded
        """
        logger.debug(f"Sending command with confirmation: {command[:50]}...")

        # Send command with newline
        self.stdin.write(command + '\n')
        await self.stdin.drain()

        full_output = ""
        start_time = time.time()

        try:
            async with asyncio.timeout(timeout):
                # Read until we see either the confirmation prompt or the admin prompt
                while True:
                    chunk = await self.stdout.read(1024)
                    if chunk:
                        self._buffer += chunk
                        full_output += chunk

                    # Check for confirmation prompt (y/n question)
                    if "'y'" in self._buffer and "'n'" in self._buffer and ":" in self._buffer:
                        # Found confirmation prompt - send confirmation
                        logger.debug(f"Confirmation prompt detected, sending '{confirmation}'")
                        self.stdin.write(confirmation + '\n')
                        await self.stdin.drain()

                        # Clear buffer and continue reading for admin prompt
                        full_output += self._buffer
                        self._buffer = ""

                        # Now read until admin: prompt
                        remaining_output = await self.read_until_prompt(
                            timeout=timeout - (time.time() - start_time)
                        )
                        return full_output + remaining_output

                    # Check if we already hit the admin prompt (no confirmation needed)
                    prompt_pattern = re.compile(r'(?m)(^|\r)\s*' + re.escape(self.prompt) + r'\s*$')
                    match = prompt_pattern.search(self._buffer)
                    if match:
                        output_text = self._buffer[:match.start()]
                        self._buffer = self._buffer[match.end():]
                        return output_text

                    # No data received - short wait before retry
                    if not chunk:
                        await asyncio.sleep(0.1)

        except TimeoutError:
            logger.error(f"Timeout waiting for confirmation or prompt after {timeout}s")
            raise CUCMCommandTimeoutError(
                f"Timeout waiting for confirmation or prompt after {timeout}s"
            )

    async def send_command_no_wait(self, command: str) -> None:
        """
        Send a command without waiting for response.

        Used for long-running commands like packet capture where we need
        to manually stop with Ctrl+C later.

        Args:
            command: Command to execute
        """
        logger.debug(f"Sending command (no wait): {command[:50]}...")
        self.stdin.write(command + '\n')
        await self.stdin.drain()

    async def send_interrupt(self) -> None:
        """
        Send Ctrl+C (interrupt) signal to stop a running command.

        Used to stop long-running commands like packet capture.
        """
        logger.debug("Sending Ctrl+C interrupt")
        self.stdin.write('\x03')  # Ctrl+C
        await self.stdin.drain()

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

            # Check if CLI is still starting up - extend timeout if needed
            cli_starting_up = "starting up" in self._session._buffer.lower()
            prompt_already_found = False
            if cli_starting_up:
                logger.info("CUCM CLI is starting up, waiting for CLI to become ready...")
                # Wait additional time for CLI to finish starting, reading any output
                try:
                    async with asyncio.timeout(max(self.connect_timeout, 60.0)):
                        while True:
                            chunk = await stdout.read(1024)
                            if chunk:
                                self._session._buffer += chunk
                                # Check if we got the prompt while waiting
                                if self.prompt in self._session._buffer:
                                    logger.info("CLI prompt appeared during startup wait")
                                    prompt_already_found = True
                                    break
                            else:
                                break  # EOF
                except asyncio.TimeoutError:
                    pass

            if prompt_already_found:
                # Prompt was already seen during startup — clear buffer up to
                # and including the prompt so execute_command starts clean.
                idx = self._session._buffer.find(self.prompt)
                if idx >= 0:
                    self._session._buffer = self._session._buffer[idx + len(self.prompt):]
                logger.info("Interactive shell session ready (prompt found during startup)")
            else:
                logger.debug(f"Banner collected ({len(self._session._buffer)} bytes), sending newline...")
                stdin.write('\n')
                await stdin.drain()

                # Now wait for prompt - use connect_timeout with a minimum of 60s
                prompt_timeout = max(self.connect_timeout, 60.0)
                logger.debug(f"Waiting for prompt (timeout={prompt_timeout}s)...")
                await self._session.read_until_prompt(timeout=prompt_timeout)
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

    async def execute_command_with_confirmation(
        self,
        command: str,
        confirmation: str = "y",
        timeout: float = 60.0
    ) -> str:
        """
        Execute a command that requires y/n confirmation.

        Used for commands like 'set trace enable' that ask:
        "Please answer 'y' for <yes> or 'n' for <no>:"

        Args:
            command: Command to execute
            confirmation: Response to send for confirmation (default: "y")
            timeout: Command timeout in seconds

        Returns:
            Command output

        Raises:
            CUCMSSHClientError: If not connected
            CUCMCommandTimeoutError: If command times out
        """
        if not self._session:
            raise CUCMSSHClientError("Not connected. Call connect() first.")

        logger.info(f"Executing command with confirmation: {command}")
        output = await self._session.send_command_with_confirmation(
            command, confirmation=confirmation, timeout=timeout
        )
        logger.debug(f"Command output length: {len(output)} bytes")

        return output

    async def send_command_no_wait(self, command: str) -> None:
        """
        Send a command without waiting for response.

        Used for long-running commands like packet capture.

        Args:
            command: Command to execute
        """
        if not self._session:
            raise CUCMSSHClientError("Not connected. Call connect() first.")

        logger.info(f"Executing command (no wait): {command}")
        await self._session.send_command_no_wait(command)

    async def send_interrupt(self) -> None:
        """
        Send Ctrl+C to interrupt a running command.
        """
        if not self._session:
            raise CUCMSSHClientError("Not connected. Call connect() first.")

        logger.info("Sending interrupt (Ctrl+C)")
        await self._session.send_interrupt()

    async def read_until_prompt(self, timeout: float = 30.0) -> str:
        """
        Read output until the prompt is seen.

        Args:
            timeout: Timeout in seconds

        Returns:
            Output text
        """
        if not self._session:
            raise CUCMSSHClientError("Not connected. Call connect() first.")

        return await self._session.read_until_prompt(timeout=timeout)

    async def recover_session(self, timeout: float = 10.0) -> None:
        """
        Attempt to recover an SSH session after an interrupt or timeout.

        Clears the buffer and sends newlines to get back to a clean prompt state.

        Args:
            timeout: Timeout in seconds for recovery

        Raises:
            CUCMSSHClientError: If not connected
            CUCMCommandTimeoutError: If recovery times out
        """
        if not self._session:
            raise CUCMSSHClientError("Not connected. Call connect() first.")

        logger.info("Attempting SSH session recovery")

        # Clear any pending data in the buffer
        self._session._buffer = ""

        # Send a newline to trigger a fresh prompt
        self._session.stdin.write('\n')
        await self._session.stdin.drain()

        # Wait briefly for the newline to be processed
        await asyncio.sleep(0.5)

        # Try to read until we see a prompt
        try:
            await self._session.read_until_prompt(timeout=timeout)
            logger.info("Session recovery successful")
        except CUCMCommandTimeoutError:
            # Try one more time with another interrupt + newline
            logger.warning("First recovery attempt failed, trying interrupt + newline")
            await self._session.send_interrupt()
            await asyncio.sleep(0.5)
            self._session._buffer = ""
            self._session.stdin.write('\n')
            await self._session.stdin.drain()
            await asyncio.sleep(0.5)
            await self._session.read_until_prompt(timeout=timeout)
            logger.info("Session recovery successful on second attempt")

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
