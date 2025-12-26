"""Unit tests for prompt responder and command builder"""

import pytest
from app.prompt_responder import PromptResponder, build_file_get_command


def test_build_file_get_command_basic():
    """Test building basic file get command"""
    cmd = build_file_get_command(
        path="platform/log/syslog",
        reltime_minutes=60
    )

    assert cmd == "file get activelog platform/log/syslog reltime 60 compress"
    assert "compress" in cmd  # Default
    assert "recurs" not in cmd  # Default is False


def test_build_file_get_command_all_options():
    """Test building command with all options"""
    cmd = build_file_get_command(
        path="cm/trace/sdl",
        reltime_minutes=120,
        compress=True,
        recurs=True,
        match=".*\\.txt$"
    )

    assert "file get activelog cm/trace/sdl" in cmd
    assert "reltime 120" in cmd
    assert "compress" in cmd
    assert "recurs" in cmd
    assert 'match ".*\\.txt$"' in cmd


def test_build_file_get_command_no_compress():
    """Test building command without compression"""
    cmd = build_file_get_command(
        path="platform/log",
        reltime_minutes=30,
        compress=False,
        recurs=False
    )

    assert "compress" not in cmd
    assert "recurs" not in cmd


def test_build_file_get_command_recurs_only():
    """Test building command with recurs but no match"""
    cmd = build_file_get_command(
        path="tomcat/logs",
        reltime_minutes=60,
        compress=True,
        recurs=True,
        match=None
    )

    assert "recurs" in cmd
    assert "match" not in cmd


def test_build_file_get_command_match_escaping():
    """Test that quotes in match pattern are escaped"""
    cmd = build_file_get_command(
        path="test/path",
        reltime_minutes=60,
        match='test"pattern'
    )

    # Quotes should be escaped
    assert 'test\\"pattern' in cmd


def test_prompt_responder_creation():
    """Test creating a PromptResponder"""
    responder = PromptResponder(
        sftp_host="sftp.example.com",
        sftp_port=22,
        sftp_username="user",
        sftp_password="pass",
        sftp_directory="/logs"
    )

    assert responder.sftp_host == "sftp.example.com"
    assert responder.sftp_port == 22
    assert responder.sftp_username == "user"
    assert responder.sftp_password == "pass"
    assert responder.sftp_directory == "/logs"
    assert len(responder.patterns) == 5  # 5 prompt patterns


def test_prompt_responder_match_sftp_host():
    """Test matching SFTP host prompt"""
    responder = PromptResponder(
        sftp_host="test.com",
        sftp_port=22,
        sftp_username="user",
        sftp_password="pass",
        sftp_directory="/logs"
    )

    # Test various formats
    matched = responder.match_prompt("SFTP host:")
    assert matched is not None
    assert matched.response_generator() == "test.com"

    matched = responder.match_prompt("sftp host:")
    assert matched is not None

    matched = responder.match_prompt("SFTP Host:")
    assert matched is not None


def test_prompt_responder_match_port():
    """Test matching SFTP port prompt"""
    responder = PromptResponder(
        sftp_host="test.com",
        sftp_port=2222,
        sftp_username="user",
        sftp_password="pass",
        sftp_directory="/logs"
    )

    matched = responder.match_prompt("SFTP port:")
    assert matched is not None
    assert matched.response_generator() == "2222"


def test_prompt_responder_match_user():
    """Test matching username prompt"""
    responder = PromptResponder(
        sftp_host="test.com",
        sftp_port=22,
        sftp_username="testuser",
        sftp_password="pass",
        sftp_directory="/logs"
    )

    matched = responder.match_prompt("User:")
    assert matched is not None
    assert matched.response_generator() == "testuser"


def test_prompt_responder_match_password():
    """Test matching password prompt"""
    responder = PromptResponder(
        sftp_host="test.com",
        sftp_port=22,
        sftp_username="user",
        sftp_password="secret123",
        sftp_directory="/logs"
    )

    matched = responder.match_prompt("Password:")
    assert matched is not None
    assert matched.response_generator() == "secret123"


def test_prompt_responder_match_directory():
    """Test matching directory prompt"""
    responder = PromptResponder(
        sftp_host="test.com",
        sftp_port=22,
        sftp_username="user",
        sftp_password="pass",
        sftp_directory="/custom/path"
    )

    matched = responder.match_prompt("Directory:")
    assert matched is not None
    assert matched.response_generator() == "/custom/path"


def test_prompt_responder_no_match():
    """Test that non-matching text returns None"""
    responder = PromptResponder(
        sftp_host="test.com",
        sftp_port=22,
        sftp_username="user",
        sftp_password="pass",
        sftp_directory="/logs"
    )

    # Random text should not match
    matched = responder.match_prompt("Some random text")
    assert matched is None

    matched = responder.match_prompt("admin:")
    assert matched is None


def test_prompt_responder_case_insensitive():
    """Test that prompt matching is case-insensitive"""
    responder = PromptResponder(
        sftp_host="test.com",
        sftp_port=22,
        sftp_username="user",
        sftp_password="pass",
        sftp_directory="/logs"
    )

    # All variations should match
    variations = [
        "SFTP HOST:",
        "sftp host:",
        "Sftp Host:",
        "SFTP host:",
    ]

    for variant in variations:
        matched = responder.match_prompt(variant)
        assert matched is not None, f"Failed to match: {variant}"


def test_prompt_responder_multiline_text():
    """Test matching prompts in multiline output"""
    responder = PromptResponder(
        sftp_host="test.com",
        sftp_port=22,
        sftp_username="user",
        sftp_password="pass",
        sftp_directory="/logs"
    )

    # Prompt on last line should match
    text = "Some output\nMore output\nSFTP host:"
    matched = responder.match_prompt(text)
    assert matched is not None

    # Prompt not on last line should not match (we only check last line)
    text = "SFTP host:\nMore output\nadmin:"
    matched = responder.match_prompt(text)
    # Should match admin: since it's the last line
    assert matched is None  # admin: is not in our patterns


def test_command_builder_order():
    """Test that command components are in correct order"""
    cmd = build_file_get_command(
        path="test/path",
        reltime_minutes=60,
        compress=True,
        recurs=True,
        match="pattern"
    )

    # Check order: base command, reltime, match, recurs, compress
    parts = cmd.split()
    assert parts[0] == "file"
    assert parts[1] == "get"
    assert parts[2] == "activelog"
    assert parts[3] == "test/path"
    assert parts[4] == "reltime"
    assert parts[5] == "60"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
