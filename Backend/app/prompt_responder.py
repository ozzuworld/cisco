"""Interactive prompt responder for CUCM CLI file get operations"""

import asyncio
import logging
import re
from typing import Dict, Optional, Callable, Tuple
from dataclasses import dataclass
from datetime import datetime, timezone

# Import SFTP timeout exception
from app.ssh_client import CUCMSFTPTimeoutError


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
        # Added proceed and host key prompts for activelog operations
        # FIX: Updated patterns to match actual CUCM CLI prompts
        self.patterns = [
            # Proceed prompts (appear before and after file sizing)
            PromptPattern(
                pattern=r"(?i)(would\s+you\s+like\s+to\s+proceed|please\s+answer\s+['\"]?y['\"]?\s+for)",
                response_generator=lambda: "y",
                description="Proceed confirmation"
            ),
            # SFTP prompts - match actual CUCM format
            PromptPattern(
                pattern=r"(?i)sftp\s+server\s+ip[:\s]*$",
                response_generator=lambda: self.sftp_host,
                description="SFTP Server IP"
            ),
            PromptPattern(
                pattern=r"(?i)sftp\s+server\s+port[:\s\[]*.*\]?[:\s]*$",
                response_generator=lambda: str(self.sftp_port),
                description="SFTP Server Port"
            ),
            PromptPattern(
                pattern=r"(?i)user\s+id[:\s]*$",
                response_generator=lambda: self.sftp_username,
                description="User ID"
            ),
            PromptPattern(
                pattern=r"(?i)password[:\s]*$",
                response_generator=lambda: self.sftp_password,
                description="Password"
            ),
            PromptPattern(
                pattern=r"(?i)download\s+directory[:\s]*$",
                response_generator=lambda: self.sftp_directory,
                description="Download Directory"
            ),
            # SSH host key confirmation
            PromptPattern(
                pattern=r"(?i)are\s+you\s+sure\s+you\s+want\s+to\s+continue\s+connecting",
                response_generator=lambda: "yes",
                description="SSH host key confirmation"
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
        prompt: str = "admin:",
        transcript_file = None,
        stop_event: Optional[asyncio.Event] = None,
        transfer_timeout: float = 180.0
    ) -> str:
        """
        Read output and respond to prompts until command completes.

        FIX: Don't complete on early admin: prompt. Wait for transfer completion
        indicators or stable idle period after prompt.

        Args:
            stdin: SSH stdin writer
            stdout: SSH stdout reader
            timeout: Maximum time to wait for command completion
            prompt: Shell prompt that indicates command completion
            transcript_file: Optional file handle to write transcript incrementally
            stop_event: Optional asyncio Event that signals stop request
            transfer_timeout: Max time for transfer after prompts answered (default 180s)

        Returns:
            Complete transcript of the interaction

        Raises:
            asyncio.TimeoutError: If timeout is exceeded or no output for 120s
        """
        transcript = []
        buffer = ""
        last_output_time = asyncio.get_event_loop().time()
        no_output_timeout = 120.0  # Fail if no output for 120s
        saw_prompt = False
        idle_start_time = None
        stable_idle_seconds = 3.0  # Wait 3s after prompt with no new prompts
        prompts_completed = False  # Track when all prompts have been answered
        prompts_completed_time = None  # Time when prompts were completed

        logger.debug("Starting prompt responder")

        try:
            async with asyncio.timeout(timeout):
                while True:
                    # Check for stop event (user requested stop)
                    if stop_event and stop_event.is_set():
                        logger.info("Stop event received during prompt responder")
                        if transcript_file:
                            transcript_file.write("\n\n[STOPPED: User requested stop]\n")
                            transcript_file.flush()
                        break

                    # Check for no-output timeout
                    current_time = asyncio.get_event_loop().time()
                    time_since_output = current_time - last_output_time

                    if time_since_output > no_output_timeout:
                        error_msg = f"SFTP upload timed out: No data received for {no_output_timeout}s"
                        logger.error(error_msg)
                        if transcript_file:
                            transcript_file.write(f"\n\n[ERROR: {error_msg}]\n")
                            transcript_file.write(f"[Last 500 chars: {buffer[-500:]}]\n")
                            transcript_file.flush()
                        raise CUCMSFTPTimeoutError(error_msg)

                    # Check for transfer timeout (hard limit after prompts are answered)
                    if prompts_completed and prompts_completed_time:
                        time_since_prompts = current_time - prompts_completed_time
                        if time_since_prompts > transfer_timeout:
                            error_msg = f"SFTP transfer timed out: {transfer_timeout}s elapsed after prompts answered"
                            logger.error(error_msg)
                            if transcript_file:
                                transcript_file.write(f"\n\n[ERROR: {error_msg}]\n")
                                transcript_file.write(f"[Last 500 chars: {buffer[-500:]}]\n")
                                transcript_file.flush()
                            raise CUCMSFTPTimeoutError(error_msg)

                    # Read a chunk with short timeout to check for idle period
                    try:
                        chunk = await asyncio.wait_for(stdout.read(1024), timeout=0.5)
                    except asyncio.TimeoutError:
                        # No data available - check if we're in stable idle after prompt
                        if saw_prompt and idle_start_time:
                            idle_duration = current_time - idle_start_time
                            if idle_duration >= stable_idle_seconds:
                                logger.info(f"Command completed: stable idle ({idle_duration:.1f}s) after shell prompt")
                                break
                        continue

                    if not chunk:
                        # EOF
                        logger.debug("EOF reached")
                        break

                    # We got output - reset idle tracking and update last output time
                    last_output_time = current_time
                    idle_start_time = None

                    buffer += chunk
                    transcript.append(chunk)

                    # Write to transcript file immediately
                    if transcript_file:
                        transcript_file.write(chunk)
                        transcript_file.flush()

                    # Check for transfer completion indicators
                    # Only check AFTER prompts are answered to avoid false positives
                    if prompts_completed:
                        if "Transfer completed" in buffer or "100%" in buffer:
                            logger.info("Transfer completion detected")
                            # Continue reading to consume the shell prompt
                            if prompt in buffer:
                                logger.info("Shell prompt detected after transfer completion")
                                break

                    # Check if we've seen the shell prompt
                    if prompt in buffer and not saw_prompt:
                        saw_prompt = True
                        idle_start_time = current_time
                        logger.debug(f"Shell prompt detected - waiting {stable_idle_seconds}s for stable idle")

                    # Check for prompts that need responses
                    matched = self.match_prompt(buffer)
                    if matched:
                        # We got a prompt - reset idle tracking
                        idle_start_time = None
                        saw_prompt = False

                        response = matched.response_generator()

                        # Log the prompt (but not the response if it's a password)
                        if "password" in matched.description.lower():
                            logger.info(f"Responding to prompt: {matched.description} (response hidden)")
                        else:
                            logger.info(f"Responding to prompt: {matched.description} = {response}")

                        # Write prompt response to transcript file
                        if transcript_file:
                            if "password" in matched.description.lower():
                                transcript_file.write(f"\n[AUTO-RESPONSE: {matched.description} = (hidden)]\n")
                            else:
                                transcript_file.write(f"\n[AUTO-RESPONSE: {matched.description} = {response}]\n")
                            transcript_file.flush()

                        # Send response
                        stdin.write(response + '\n')
                        await stdin.drain()

                        # Mark prompts as completed after the directory prompt
                        # (the last prompt before transfer starts)
                        if "directory" in matched.description.lower():
                            prompts_completed = True
                            prompts_completed_time = current_time
                            logger.info(f"All SFTP prompts answered, starting transfer timeout ({transfer_timeout}s)")
                            # After the last prompt, keep the buffer in case
                            # transfer completion data arrived in the same chunk
                            buffer = buffer[buffer.rfind('\n') + 1:] if '\n' in buffer else ""
                        else:
                            # Clear buffer to wait for next prompt
                            buffer = ""

        except asyncio.TimeoutError as e:
            # Convert generic timeout to SFTP timeout
            error_msg = str(e) if str(e) else f"SFTP upload timed out after {timeout}s"
            logger.error(f"Prompt responder timed out: {error_msg}")
            if transcript_file:
                transcript_file.write(f"\n\n[TIMEOUT: {error_msg}]\n")
                transcript_file.flush()
            raise CUCMSFTPTimeoutError(error_msg) from e

        full_transcript = ''.join(transcript)
        logger.debug(f"Prompt responder completed. Transcript length: {len(full_transcript)} bytes")

        return full_transcript


def compute_reltime_from_range(start_time: datetime, end_time: datetime) -> Tuple[str, int]:
    """
    Convert absolute time range to CUCM reltime format.

    Computes the relative time from now back to start_time and selects
    the most appropriate CUCM time unit (minutes/hours/days/weeks/months).

    Args:
        start_time: Start of the desired time range
        end_time: End of the desired time range (used for validation only)

    Returns:
        Tuple of (unit, value) where:
        - unit: One of "minutes", "hours", "days", "weeks", "months"
        - value: Integer value for that unit

    Example:
        >>> start = datetime.now(timezone.utc) - timedelta(hours=3)
        >>> end = datetime.now(timezone.utc)
        >>> compute_reltime_from_range(start, end)
        ('hours', 3)

    Note:
        CUCM collects logs from (now - reltime) to now, so we compute
        reltime as the difference between now and start_time.
    """
    # Get current time
    now = datetime.now(timezone.utc)

    # Make start_time timezone-aware if needed
    start_aware = start_time if start_time.tzinfo else start_time.replace(tzinfo=timezone.utc)

    # Compute difference between now and start_time
    delta = now - start_aware
    total_seconds = delta.total_seconds()

    # Select best unit based on the time difference
    # Priority: Use the largest unit that gives a whole number >= 1

    # Months (approximate: 30 days)
    months = total_seconds / (30 * 24 * 3600)
    if months >= 1 and months == int(months):
        return ("months", int(months))

    # Weeks (7 days)
    weeks = total_seconds / (7 * 24 * 3600)
    if weeks >= 1 and weeks == int(weeks):
        return ("weeks", int(weeks))

    # Days
    days = total_seconds / (24 * 3600)
    if days >= 1 and days == int(days):
        return ("days", int(days))

    # Hours
    hours = total_seconds / 3600
    if hours >= 1 and hours == int(hours):
        return ("hours", int(hours))

    # Minutes (default fallback)
    minutes = int(total_seconds / 60)
    if minutes < 1:
        minutes = 1  # Minimum 1 minute

    return ("minutes", minutes)


def build_file_get_command(
    path: str,
    reltime_value: int,
    reltime_unit: str = "minutes",
    compress: bool = True,
    recurs: bool = False,
    match: Optional[str] = None
) -> str:
    """
    Build a `file get activelog` command with appropriate options.

    Args:
        path: Log path to collect (e.g., "syslog/messages*")
        reltime_value: Relative time window value
        reltime_unit: Relative time unit (minutes/hours/days/weeks/months)
        compress: Whether to compress the files
        recurs: Whether to collect recursively
        match: Optional regex pattern to match filenames

    Returns:
        Complete command string

    Examples:
        >>> build_file_get_command("syslog/messages*", 60, "minutes", compress=True)
        'file get activelog syslog/messages* reltime minutes 60 compress'
        >>> build_file_get_command("cm/trace/sdl*", 3, "hours", compress=True)
        'file get activelog cm/trace/sdl* reltime hours 3 compress'
    """
    # Start with base command: Support dynamic time units
    cmd = f"file get activelog {path} reltime {reltime_unit} {reltime_value}"

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
