"""Unit tests for CUCM CLI output parsers"""

import pytest
from app.parsers import parse_show_network_cluster, strip_ansi_codes
from app.models import ClusterNode


# Sample output provided in requirements (exact copy)
SAMPLE_OUTPUT = """admin:show network cluster
104.156.46.39 den04wx051ccm01.wx051.webexcce.com den04wx051ccm01 Subscriber callmanager DBSub authenticated using TCP since Fri Mar 28 06:07:53 2025
104.156.47.39 aus05wx051ccm01.wx051.webexcce.com aus05wx051ccm01 Subscriber callmanager DBSub authenticated using TCP since Sat Aug 9 02:49:37 2025
104.156.46.17 den02wx051ccm01.wx051.webexcce.com den02wx051ccm01 Subscriber callmanager DBSub authenticated using TCP since Fri Mar 28 06:07:43 2025
104.156.47.17 aus03wx051ccm01.wx051.webexcce.com aus03wx051ccm01 Subscriber callmanager DBSub authenticated using TCP since Sat May 31 04:08:34 2025
104.156.46.18 den01wx051imp01.wx051.webexcce.com den01wx051imp01 Subscriber cups DBPub authenticated using TCP since Fri Mar 28 06:07:53 2025
104.156.47.18 aus02wx051imp01.wx051.webexcce.com aus02wx051imp01 Subscriber cups DBSub authenticated using TCP since Sat Aug 9 02:49:42 2025
104.156.46.16 den01wx051ccm01.wx051.webexcce.com den01wx051ccm01 Publisher callmanager DBPub authenticated

Server Table (processnode) Entries
----------------------------------
den01wx051ccm01.wx051.webexcce.com
..."""


def test_parse_sample_output():
    """Test parsing the exact sample output from requirements"""
    nodes = parse_show_network_cluster(SAMPLE_OUTPUT)

    # Should parse exactly 7 nodes
    assert len(nodes) == 7, f"Expected 7 nodes, got {len(nodes)}"

    # Extract IPs for easier verification
    node_ips = {node.ip for node in nodes}
    expected_ips = {
        "104.156.46.39",
        "104.156.47.39",
        "104.156.46.17",
        "104.156.47.17",
        "104.156.46.18",
        "104.156.47.18",
        "104.156.46.16",
    }
    assert node_ips == expected_ips, f"IP mismatch: {node_ips} != {expected_ips}"

    # Find publisher node
    publishers = [n for n in nodes if n.role == "Publisher"]
    assert len(publishers) == 1, "Should have exactly one Publisher"

    publisher = publishers[0]
    assert publisher.ip == "104.156.46.16"
    assert publisher.fqdn == "den01wx051ccm01.wx051.webexcce.com"
    assert publisher.host == "den01wx051ccm01"
    assert publisher.role == "Publisher"
    assert publisher.product == "callmanager"
    assert publisher.dbrole == "DBPub"

    # Verify subscribers
    subscribers = [n for n in nodes if n.role == "Subscriber"]
    assert len(subscribers) == 6, "Should have 6 Subscribers"

    # Check a specific subscriber
    den04_node = next((n for n in nodes if n.ip == "104.156.46.39"), None)
    assert den04_node is not None
    assert den04_node.fqdn == "den04wx051ccm01.wx051.webexcce.com"
    assert den04_node.host == "den04wx051ccm01"
    assert den04_node.role == "Subscriber"
    assert den04_node.product == "callmanager"
    assert den04_node.dbrole == "DBSub"

    # Check CUPS node
    cups_nodes = [n for n in nodes if n.product == "cups"]
    assert len(cups_nodes) == 2, "Should have 2 CUPS nodes"


def test_parse_with_server_table_section():
    """Test that parsing stops at 'Server Table' section"""
    output = """admin:show network cluster
104.156.46.16 den01wx051ccm01.wx051.webexcce.com den01wx051ccm01 Publisher callmanager DBPub authenticated
104.156.46.17 den02wx051ccm01.wx051.webexcce.com den02wx051ccm01 Subscriber callmanager DBSub authenticated

Server Table (processnode) Entries
----------------------------------
104.156.99.99 fake.example.com fake Subscriber callmanager DBSub authenticated
"""

    nodes = parse_show_network_cluster(output)

    # Should only parse the 2 nodes before "Server Table"
    assert len(nodes) == 2
    assert all(node.ip != "104.156.99.99" for node in nodes)


def test_parse_empty_output():
    """Test parsing empty output"""
    nodes = parse_show_network_cluster("")
    assert len(nodes) == 0


def test_parse_no_valid_nodes():
    """Test parsing output with no valid node lines"""
    output = """admin:show network cluster
Some random text
No valid node information here
Server Table (processnode) Entries
"""

    nodes = parse_show_network_cluster(output)
    assert len(nodes) == 0


def test_parse_with_ansi_codes():
    """Test that ANSI escape codes are stripped"""
    output = """admin:show network cluster
\x1b[32m104.156.46.16\x1b[0m den01wx051ccm01.wx051.webexcce.com den01wx051ccm01 Publisher callmanager DBPub authenticated
104.156.46.17 \x1b[1mden02wx051ccm01.wx051.webexcce.com\x1b[0m den02wx051ccm01 Subscriber callmanager DBSub authenticated
"""

    nodes = parse_show_network_cluster(output)

    assert len(nodes) == 2
    # Verify IPs are clean (no ANSI codes)
    assert nodes[0].ip == "104.156.46.16" or nodes[0].ip == "104.156.46.17"


def test_strip_ansi_codes():
    """Test ANSI code stripping function"""
    # Color codes
    text_with_color = "\x1b[32mGreen text\x1b[0m"
    assert strip_ansi_codes(text_with_color) == "Green text"

    # Bold
    text_with_bold = "\x1b[1mBold text\x1b[0m"
    assert strip_ansi_codes(text_with_bold) == "Bold text"

    # Multiple codes
    complex_text = "\x1b[32;1mGreen bold\x1b[0m normal \x1b[31mred\x1b[0m"
    assert strip_ansi_codes(complex_text) == "Green bold normal red"

    # No codes
    plain_text = "Plain text"
    assert strip_ansi_codes(plain_text) == "Plain text"


def test_deduplication_by_ip():
    """Test that duplicate IPs are deduplicated"""
    output = """admin:show network cluster
104.156.46.16 den01wx051ccm01.wx051.webexcce.com den01wx051ccm01 Publisher callmanager DBPub authenticated
104.156.46.16 duplicate.example.com duplicate Publisher callmanager DBPub authenticated
104.156.46.17 den02wx051ccm01.wx051.webexcce.com den02wx051ccm01 Subscriber callmanager DBSub authenticated
"""

    nodes = parse_show_network_cluster(output)

    # Should only have 2 unique IPs
    assert len(nodes) == 2
    node_ips = {node.ip for node in nodes}
    assert node_ips == {"104.156.46.16", "104.156.46.17"}


def test_invalid_ip_format():
    """Test that invalid IP addresses are filtered out"""
    output = """admin:show network cluster
104.156.46.16 den01wx051ccm01.wx051.webexcce.com den01wx051ccm01 Publisher callmanager DBPub authenticated
999.999.999.999 invalid.example.com invalid Subscriber callmanager DBSub authenticated
not-an-ip example.com host Subscriber callmanager DBSub authenticated
104.156.46.17 den02wx051ccm01.wx051.webexcce.com den02wx051ccm01 Subscriber callmanager DBSub authenticated
"""

    nodes = parse_show_network_cluster(output)

    # Should only parse the 2 valid nodes
    assert len(nodes) == 2
    node_ips = {node.ip for node in nodes}
    assert node_ips == {"104.156.46.16", "104.156.46.17"}


def test_invalid_role():
    """Test that lines with invalid roles are filtered out"""
    output = """admin:show network cluster
104.156.46.16 den01wx051ccm01.wx051.webexcce.com den01wx051ccm01 Publisher callmanager DBPub authenticated
104.156.46.17 den02wx051ccm01.wx051.webexcce.com den02wx051ccm01 InvalidRole callmanager DBSub authenticated
104.156.46.18 den03wx051ccm01.wx051.webexcce.com den03wx051ccm01 Subscriber callmanager DBSub authenticated
"""

    nodes = parse_show_network_cluster(output)

    # Should only parse the 2 valid nodes (with valid roles)
    assert len(nodes) == 2
    node_ips = {node.ip for node in nodes}
    assert node_ips == {"104.156.46.16", "104.156.46.18"}


def test_incomplete_lines():
    """Test that lines with insufficient fields are skipped"""
    output = """admin:show network cluster
104.156.46.16 den01wx051ccm01.wx051.webexcce.com den01wx051ccm01 Publisher callmanager DBPub authenticated
104.156.46.17 incomplete
short line
104.156.46.18 den03wx051ccm01.wx051.webexcce.com den03wx051ccm01 Subscriber callmanager DBSub authenticated
"""

    nodes = parse_show_network_cluster(output)

    # Should only parse the 2 complete nodes
    assert len(nodes) == 2
    node_ips = {node.ip for node in nodes}
    assert node_ips == {"104.156.46.16", "104.156.46.18"}


def test_raw_field_preserved():
    """Test that the raw line is preserved in the node"""
    output = """admin:show network cluster
104.156.46.16 den01wx051ccm01.wx051.webexcce.com den01wx051ccm01 Publisher callmanager DBPub authenticated using TCP since Fri Mar 28
"""

    nodes = parse_show_network_cluster(output)

    assert len(nodes) == 1
    # The raw field should contain the original line (stripped)
    assert "104.156.46.16" in nodes[0].raw
    assert "Publisher" in nodes[0].raw
    assert "authenticated" in nodes[0].raw


def test_multiple_product_types():
    """Test parsing different product types (callmanager, cups, etc)"""
    output = """admin:show network cluster
104.156.46.16 ccm01.example.com ccm01 Publisher callmanager DBPub authenticated
104.156.46.17 imp01.example.com imp01 Subscriber cups DBSub authenticated
104.156.46.18 cube01.example.com cube01 Subscriber cube DBSub authenticated
"""

    nodes = parse_show_network_cluster(output)

    assert len(nodes) == 3

    # Check products
    products = {node.product for node in nodes}
    assert products == {"callmanager", "cups", "cube"}


def test_various_dbroles():
    """Test parsing different DB roles"""
    output = """admin:show network cluster
104.156.46.16 ccm01.example.com ccm01 Publisher callmanager DBPub authenticated
104.156.46.17 ccm02.example.com ccm02 Subscriber callmanager DBSub authenticated
"""

    nodes = parse_show_network_cluster(output)

    assert len(nodes) == 2

    # Check DB roles
    dbroles = {node.dbrole for node in nodes}
    assert dbroles == {"DBPub", "DBSub"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
