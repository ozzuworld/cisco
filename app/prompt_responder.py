"""Interactive prompt responder for CUCM CLI file get operations"""

import asyncio
import logging
import re
from typing import Dict, Optional, Callable
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class PromptPattern:
    """Defines a prompt pattern and its response"""
    pattern: str  # Regex pattern to match
    response_generator: Callable[[], str]  # Function that generates the response
    description: str  # Human-readable description


class PromptResponder:
    """
    Handles interactive prompts from CUCM CLI during file get operations.

    The `file get activelog` command prompts for SFTP parameters:
    - SFTP host
    - SFTP port
    - Username
    - Password
    - Remote directory

    This class detects these prompts and responds appropriately.
    """

    def __init__(
        self,
        sftp_host: str,
        sftp_port: int,
        sftp_username: str,
        sftp_password: str,
        sftp_directory: str
    ):
        """
        Initialize prompt responder with SFTP connection details.

        Args:
            sftp_host: SFTP server hostname/IP
            sftp_port: SFTP server port
            sftp_username: SFTP username
            sftp_password: SFTP password (never logged)
            sftp_directory: Remote directory path
        """
        self.sftp_host = sftp_host
        self.sftp_port = sftp_port
        self.sftp_username = sftp_username
        self.sftp_password = sftp_password  # NEVER log this
        self.sftp_directory = sftp_directory

        # Define prompt patterns (case-insensitive)
        self.patterns = [
            PromptPattern(
                pattern=r"(?i)sftp\s+host[:\s]*$",
                response_generator=lambda: self.sftp_host,
                description="SFTP Host"
            ),
            PromptPattern(
                pattern=r"(?i)sftp\s+port[:\s]*$",
                response_generator=lambda: str(self.sftp_port),
                description="SFTP Port"
            ),
            PromptPattern(
                pattern=r"(?i)user[:\s]*$",
                response_generator=lambda: self.sftp_username,
                description="Username"
            ),
            PromptPattern(
                pattern=r"(?i)password[:\s]*$",
                response_generator=lambda: self.sftp_password,
                description="Password"
            ),
            PromptPattern(
                pattern=r"(?i)directory[:\s]*$",
                response_generator=lambda: self.sftp_directory,
                description="Directory"
            ),
        ]

    def match_prompt(self, text: str) -> Optional[PromptPattern]:
        """
        Try to match text against known prompts.

        Args:
            text: Text to match (usually the last line or few lines)

        Returns:
            PromptPattern if matched, None otherwise
        """
        # Check the last line of the text
        lines = text.strip().split('\n')
        if not lines:
            return None

        last_line = lines[-1].strip()

        for pattern in self.patterns:
            if re.search(pattern.pattern, last_line):
                return pattern

        return None

    async def respond_to_prompts(
        self,
        stdin,
        stdout,
        timeout: float = 300.0,
        prompt: str = "admin:"
    ) -> str:
        """
        Read output and respond to prompts until command completes.

        Args:
            stdin: SSH stdin writer
            stdout: SSH stdout reader
            timeout: Maximum time to wait for command completion
            prompt: Shell prompt that indicates command completion

        Returns:
            Complete transcript of the interaction

        Raises:
            asyncio.TimeoutError: If timeout is exceeded
        """
        transcript = []
        buffer = ""

        logger.debug("Starting prompt responder")

        try:
            async with asyncio.timeout(timeout):
                while True:
                    # Read a chunk
                    chunk = await stdout.read(1024)
                    if not chunk:
                        # EOF
                        logger.debug("EOF reached")
                        break

                    buffer += chunk
                    transcript.append(chunk)

                    # Check if we've returned to the shell prompt (command completed)
                    if prompt in buffer:
                        logger.info("Shell prompt detected - command completed")
                        break

                    # Check for prompts that need responses
                    matched = self.match_prompt(buffer)
                    if matched:
                        response = matched.response_generator()

                        # Log the prompt (but not the response if it's a password)
                        if "password" in matched.description.lower():
                            logger.info(f"Responding to prompt: {matched.description} (response hidden)")
                        else:
                            logger.info(f"Responding to prompt: {matched.description} = {response}")

                        # Send response
                        stdin.write(response + '\n')
                        await stdin.drain()

                        # Clear buffer to wait for next prompt
                        buffer = ""

        except asyncio.TimeoutError:
            logger.error(f"Prompt responder timed out after {timeout}s")
            raise

        full_transcript = ''.join(transcript)
        logger.debug(f"Prompt responder completed. Transcript length: {len(full_transcript)} bytes")

        return full_transcript


def build_file_get_command(
    path: str,
    reltime_minutes: int,
    compress: bool = True,
    recurs: bool = False,
    match: Optional[str] = None
) -> str:
    """
    Build a `file get activelog` command with appropriate options.

    Args:
        path: Log path to collect (e.g., "platform/log/syslog")
        reltime_minutes: Relative time window in minutes
        compress: Whether to compress the files
        recurs: Whether to collect recursively
        match: Optional regex pattern to match filenames

    Returns:
        Complete command string

    Example:
        >>> build_file_get_command("cm/trace/sdl", 60, compress=True, recurs=True)
        'file get activelog cm/trace/sdl reltime 60 compress recurs'
    """
    # Start with base command
    cmd = f"file get activelog {path} reltime {reltime_minutes}"

    # Add optional flags
    if match:
        # Escape quotes in the pattern
        escaped_match = match.replace('"', '\\"')
        cmd += f' match "{escaped_match}"'

    if recurs:
        cmd += " recurs"

    if compress:
        cmd += " compress"

    return cmd
