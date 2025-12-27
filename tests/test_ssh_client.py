"""Tests for SSH client prompt detection and output capture"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock
from app.ssh_client import InteractiveShellSession, CUCMCommandTimeoutError


class FakeSSHReader:
    """Fake SSH reader that simulates reading from a stream"""

    def __init__(self, data_chunks):
        """
        Args:
            data_chunks: List of (data, delay) tuples
        """
        self.data_chunks = data_chunks
        self.index = 0

    async def read(self, size):
        """Simulate reading from stream with delays"""
        if self.index >= len(self.data_chunks):
            # EOF
            return ""

        data, delay = self.data_chunks[self.index]
        self.index += 1

        if delay > 0:
            await asyncio.sleep(delay)

        return data


class FakeSSHWriter:
    """Fake SSH writer"""

    def __init__(self):
        self.written = []

    def write(self, data):
        self.written.append(data)

    async def drain(self):
        pass

    def close(self):
        pass


@pytest.mark.asyncio
async def test_read_until_prompt_standard():
    """Test reading until standard prompt: admin:"""
    stdout = FakeSSHReader([
        ("Command output line 1\n", 0.1),
        ("Command output line 2\n", 0.1),
        ("admin:", 0.1),
    ])
    stdin = FakeSSHWriter()
    stderr = FakeSSHReader([])

    session = InteractiveShellSession(stdin, stdout, stderr, prompt="admin:")

    output = await session.read_until_prompt(timeout=5.0, min_read_duration=0.2)

    assert "Command output line 1" in output
    assert "Command output line 2" in output
    assert "admin:" not in output  # Prompt should be excluded


@pytest.mark.asyncio
async def test_read_until_prompt_with_carriage_return():
    """Test reading until prompt with \\r prefix: \\radmin:"""
    stdout = FakeSSHReader([
        ("Output text\r\n", 0.1),
        ("\radmin:", 0.1),
    ])
    stdin = FakeSSHWriter()
    stderr = FakeSSHReader([])

    session = InteractiveShellSession(stdin, stdout, stderr, prompt="admin:")

    output = await session.read_until_prompt(timeout=5.0, min_read_duration=0.2)

    assert "Output text" in output
    assert "admin:" not in output


@pytest.mark.asyncio
async def test_read_until_prompt_with_crlf_suffix():
    """Test reading until prompt with \\r\\n suffix: admin:\\r\\n"""
    stdout = FakeSSHReader([
        ("Some output\n", 0.1),
        ("admin:\r\n", 0.1),
    ])
    stdin = FakeSSHWriter()
    stderr = FakeSSHReader([])

    session = InteractiveShellSession(stdin, stdout, stderr, prompt="admin:")

    output = await session.read_until_prompt(timeout=5.0, min_read_duration=0.2)

    assert "Some output" in output
    assert "admin:" not in output


@pytest.mark.asyncio
async def test_read_until_prompt_with_spaces():
    """Test reading until prompt with spaces:  admin:  """
    stdout = FakeSSHReader([
        ("Output\n", 0.1),
        (" admin: ", 0.1),
    ])
    stdin = FakeSSHWriter()
    stderr = FakeSSHReader([])

    session = InteractiveShellSession(stdin, stdout, stderr, prompt="admin:")

    output = await session.read_until_prompt(timeout=5.0, min_read_duration=0.2)

    assert "Output" in output


@pytest.mark.asyncio
async def test_read_until_prompt_minimum_duration():
    """Test that minimum read duration prevents early exit"""
    # Prompt arrives immediately but we should wait min_read_duration
    stdout = FakeSSHReader([
        ("admin:", 0.0),  # Prompt arrives immediately
        ("More output\n", 0.3),  # More data arrives after 0.3s
        ("admin:", 0.1),  # Final prompt
    ])
    stdin = FakeSSHWriter()
    stderr = FakeSSHReader([])

    session = InteractiveShellSession(stdin, stdout, stderr, prompt="admin:")

    # With min_read_duration=0.5, should wait and collect all output
    output = await session.read_until_prompt(timeout=5.0, min_read_duration=0.5)

    # Should have collected the output between the two prompts
    assert "More output" in output


@pytest.mark.asyncio
async def test_read_until_prompt_preserves_buffer():
    """Test that data after prompt is preserved in buffer"""
    stdout = FakeSSHReader([
        ("Output\nadmin:\nExtra data", 0.1),
    ])
    stdin = FakeSSHWriter()
    stderr = FakeSSHReader([])

    session = InteractiveShellSession(stdin, stdout, stderr, prompt="admin:")

    output = await session.read_until_prompt(timeout=5.0, min_read_duration=0.2)

    assert "Output" in output
    assert "admin:" not in output
    # Buffer should preserve "Extra data"
    assert session._buffer == "\nExtra data"


@pytest.mark.asyncio
async def test_read_until_prompt_timeout():
    """Test timeout behavior"""
    stdout = FakeSSHReader([
        ("Output without prompt\n", 0.1),
        ("More output\n", 5.0),  # Long delay
    ])
    stdin = FakeSSHWriter()
    stderr = FakeSSHReader([])

    session = InteractiveShellSession(stdin, stdout, stderr, prompt="admin:")

    # Should timeout waiting for prompt
    with pytest.raises(CUCMCommandTimeoutError):
        await session.read_until_prompt(timeout=1.0, min_read_duration=0.2)


@pytest.mark.asyncio
async def test_read_until_prompt_empty_output():
    """Test handling of empty/tiny output"""
    stdout = FakeSSHReader([
        ("Some banner\n", 0.1),
        ("admin:", 0.1),
    ])
    stdin = FakeSSHWriter()
    stderr = FakeSSHReader([])

    session = InteractiveShellSession(stdin, stdout, stderr, prompt="admin:")

    # Should handle tiny output and log warning
    output = await session.read_until_prompt(timeout=5.0, min_read_duration=0.2)

    # Output should be the banner
    assert "banner" in output.lower()
    assert "admin:" not in output


@pytest.mark.asyncio
async def test_send_command():
    """Test sending command and reading response"""
    stdout = FakeSSHReader([
        ("show network cluster\n", 0.1),  # Echo of command
        ("Node1  10.10.10.1\n", 0.1),
        ("Node2  10.10.10.2\n", 0.1),
        ("admin:", 0.1),
    ])
    stdin = FakeSSHWriter()
    stderr = FakeSSHReader([])

    session = InteractiveShellSession(stdin, stdout, stderr, prompt="admin:")

    output = await session.send_command("show network cluster", timeout=5.0)

    # Should have sent command with newline
    assert "show network cluster\n" in stdin.written

    # Should have captured output
    assert "Node1" in output
    assert "Node2" in output
    assert "admin:" not in output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
