"""
Network utilities for CUCM Log Collector.

Provides functions for auto-detecting the host's IP address.
"""

import logging
import socket
from typing import Optional

logger = logging.getLogger(__name__)


def get_host_ip() -> Optional[str]:
    """
    Auto-detect the host's external IP address.

    Uses a socket trick: connects to an external IP (doesn't actually send data)
    and checks which local IP was used. This reliably finds the IP of the
    interface that routes to external networks.

    Returns:
        The detected IP address, or None if detection fails
    """
    try:
        # Create a UDP socket (doesn't actually connect)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connect to Google DNS - this doesn't send any data,
            # just determines which interface would be used
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            logger.info(f"Auto-detected host IP: {ip}")
            return ip
    except Exception as e:
        logger.warning(f"Failed to auto-detect IP via socket: {e}")

    # Fallback: try to get from hostname
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and not ip.startswith("127."):
            logger.info(f"Auto-detected host IP from hostname: {ip}")
            return ip
    except Exception as e:
        logger.warning(f"Failed to get IP from hostname: {e}")

    # Last resort fallback
    logger.warning("Could not auto-detect IP, falling back to 127.0.0.1")
    return None


def get_all_ips() -> list[str]:
    """
    Get all non-localhost IP addresses for this host.

    Useful for logging/debugging to show available IPs.

    Returns:
        List of IP addresses
    """
    ips = []
    try:
        hostname = socket.gethostname()
        # Get all addresses for hostname
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception as e:
        logger.debug(f"Error getting all IPs: {e}")

    # Also try the socket method
    detected = get_host_ip()
    if detected and detected not in ips:
        ips.insert(0, detected)

    return ips
