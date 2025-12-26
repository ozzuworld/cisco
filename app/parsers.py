"""Parsers for CUCM CLI command outputs"""

import re
from typing import List, Dict
from app.models import ClusterNode


def strip_ansi_codes(text: str) -> str:
    """
    Remove ANSI escape codes from text.

    Args:
        text: Raw text that may contain ANSI codes

    Returns:
        Text with ANSI codes removed
    """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def parse_show_network_cluster(raw_output: str) -> List[ClusterNode]:
    """
    Parse the output of 'show network cluster' command.

    The command output contains a top block with node information, followed by
    a "Server Table" section. We only parse the top block.

    Example line format:
    104.156.46.39 den04wx051ccm01.wx051.webexcce.com den04wx051ccm01 Subscriber callmanager DBSub authenticated using TCP since Fri Mar 28 06:07:53 2025

    Args:
        raw_output: Raw output from the 'show network cluster' command

    Returns:
        List of ClusterNode objects, deduplicated by IP address
    """
    # Strip ANSI codes first
    clean_output = strip_ansi_codes(raw_output)

    nodes: Dict[str, ClusterNode] = {}  # Use dict for deduplication by IP

    # Split into lines
    lines = clean_output.split('\n')

    # Process lines until we hit "Server Table" section
    for line in lines:
        line = line.strip()

        # Stop processing when we hit the Server Table section
        if line.startswith('Server Table'):
            break

        # Skip empty lines or the command echo
        if not line or line.startswith('admin:'):
            continue

        # Try to parse the line
        # Expected format: IP FQDN HOST ROLE PRODUCT DBROLE [additional info...]
        # Split by whitespace and expect at least 6 fields
        parts = line.split()

        if len(parts) < 6:
            continue

        # Extract fields
        ip = parts[0]
        fqdn = parts[1]
        host = parts[2]
        role = parts[3]  # Publisher or Subscriber
        product = parts[4]  # callmanager, cups, etc.
        dbrole = parts[5]  # DBPub or DBSub

        # Validate IP format (basic check)
        if not _is_valid_ip_format(ip):
            continue

        # Validate role
        if role not in ['Publisher', 'Subscriber']:
            continue

        # Create node object (deduplicate by IP)
        if ip not in nodes:
            nodes[ip] = ClusterNode(
                ip=ip,
                fqdn=fqdn,
                host=host,
                role=role,
                product=product,
                dbrole=dbrole,
                raw=line
            )

    return list(nodes.values())


def _is_valid_ip_format(ip: str) -> bool:
    """
    Basic validation to check if a string looks like an IP address.

    Args:
        ip: String to validate

    Returns:
        True if it looks like an IP address, False otherwise
    """
    # Simple pattern: four groups of digits separated by dots
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(pattern, ip):
        return False

    # Check each octet is 0-255
    octets = ip.split('.')
    try:
        return all(0 <= int(octet) <= 255 for octet in octets)
    except ValueError:
        return False
