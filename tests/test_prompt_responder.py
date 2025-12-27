"""Unit tests for prompt responder and command builder"""

import pytest
from app.prompt_responder import PromptResponder, build_file_get_command


def test_build_file_get_command_basic():
    """Test building basic file get command"""
    cmd = build_file_get_command(
        path="syslog/messages*",
        reltime_minutes=60
    )

    # BE-017: reltime should include 'minutes' unit
    assert cmd == "file get activelog syslog/messages* reltime minutes 60 compress"
    assert "reltime minutes 60" in cmd
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
    # BE-017: reltime should include 'minutes' unit
    assert "reltime minutes 120" in cmd
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
    # BE-017: 7 patterns (proceed, SFTP host, port, user, password, directory, host key)
    assert len(responder.patterns) == 7


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

    # BE-017: Check order includes 'minutes' unit
    parts = cmd.split()
    assert parts[0] == "file"
    assert parts[1] == "get"
    assert parts[2] == "activelog"
    assert parts[3] == "test/path"
    assert parts[4] == "reltime"
    assert parts[5] == "minutes"
    assert parts[6] == "60"


# ============================================================================
# BE-017 Tests - New prompt patterns and activelog support
# ============================================================================


def test_be017_reltime_always_includes_minutes():
    """BE-017: Verify reltime always includes 'minutes' unit"""
    cmd = build_file_get_command("syslog/messages*", reltime_minutes=30)
    assert "reltime minutes 30" in cmd

    cmd = build_file_get_command("syslog/secure*", reltime_minutes=120)
    assert "reltime minutes 120" in cmd


def test_be017_prompt_responder_proceed_confirmation():
    """BE-017: Test matching 'Would you like to proceed [y/n]?' prompt"""
    responder = PromptResponder(
        sftp_host="test.com",
        sftp_port=22,
        sftp_username="user",
        sftp_password="pass",
        sftp_directory="/logs"
    )

    # Test various formats of proceed prompt
    variations = [
        "Would you like to proceed [y/n]?",
        "Would you like to proceed [ y / n ]?",
        "would you like to proceed [y/n]?",
        "WOULD YOU LIKE TO PROCEED [Y/N]?",
    ]

    for variant in variations:
        matched = responder.match_prompt(variant)
        assert matched is not None, f"Failed to match: {variant}"
        assert matched.response_generator() == "y"


def test_be017_prompt_responder_host_key_confirmation():
    """BE-017: Test matching SSH host key confirmation prompt"""
    responder = PromptResponder(
        sftp_host="test.com",
        sftp_port=22,
        sftp_username="user",
        sftp_password="pass",
        sftp_directory="/logs"
    )

    # Test various formats of host key prompt
    variations = [
        "Are you sure you want to continue connecting (yes/no)?",
        "are you sure you want to continue connecting (yes/no)?",
        "ARE YOU SURE YOU WANT TO CONTINUE CONNECTING (YES/NO)?",
        "Are you sure you want to continue connecting ( yes / no )?",
    ]

    for variant in variations:
        matched = responder.match_prompt(variant)
        assert matched is not None, f"Failed to match: {variant}"
        assert matched.response_generator() == "yes"


def test_be017_activelog_paths():
    """BE-017: Test that activelog paths work correctly"""
    # Test syslog paths
    cmd = build_file_get_command("syslog/messages*", 60)
    assert "syslog/messages*" in cmd

    cmd = build_file_get_command("syslog/secure*", 120)
    assert "syslog/secure*" in cmd

    cmd = build_file_get_command("syslog/maillog*", 30)
    assert "syslog/maillog*" in cmd


def test_be017_all_prompts_in_order():
    """BE-017: Verify all prompt patterns are registered in correct order"""
    responder = PromptResponder(
        sftp_host="test.com",
        sftp_port=22,
        sftp_username="user",
        sftp_password="pass",
        sftp_directory="/logs"
    )

    # Should have 7 patterns total
    assert len(responder.patterns) == 7

    # Verify proceed prompt is first (most general)
    assert "proceed" in responder.patterns[0].description.lower()

    # Verify host key prompt is last (also general)
    assert "host key" in responder.patterns[6].description.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
