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


def is_docker_internal_ip(ip: str) -> bool:
    """
    Check if an IP address appears to be a Docker internal network IP.

    Docker typically uses 172.17.x.x for the default bridge and
    172.18-31.x.x for user-defined networks.

    Args:
        ip: IP address to check

    Returns:
        True if the IP looks like a Docker internal IP
    """
    if not ip:
        return False
    # Docker bridge networks typically use 172.17-31.x.x
    parts = ip.split('.')
    if len(parts) == 4 and parts[0] == '172':
        try:
            second_octet = int(parts[1])
            if 17 <= second_octet <= 31:
                return True
        except ValueError:
            pass
    return False


def get_local_ip_for_target(target_ip: str) -> Optional[str]:
    """
    Get the local IP address that would be used to reach a specific target.

    This is crucial for VPN scenarios: when the target CUCM is on a VPN network,
    this function finds the local VPN interface IP that can reach it, rather than
    the default internet-facing interface.

    Note: When running in Docker with bridge networking, this may return a Docker
    internal IP (172.x.x.x) instead of the host's VPN IP. For VPN scenarios,
    use --network host or set SFTP_HOST manually.

    Args:
        target_ip: The IP address of the target device (e.g., CUCM)

    Returns:
        The local IP address that routes to the target, or None if detection fails
    """
    try:
        # Create a UDP socket (doesn't actually send data)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connect to the target IP - this determines which local interface
            # would be used to reach that specific target
            s.connect((target_ip, 1))
            local_ip = s.getsockname()[0]

            # Warn if we detected a Docker internal IP - this won't work for
            # VPN scenarios where CUCM needs to connect back
            if is_docker_internal_ip(local_ip):
                logger.warning(
                    f"Detected Docker internal IP {local_ip} for target {target_ip}. "
                    f"CUCM may not be able to reach this IP. For VPN scenarios, "
                    f"use 'docker run --network host' or set SFTP_HOST to your VPN IP."
                )
            else:
                logger.info(f"Auto-detected local IP for target {target_ip}: {local_ip}")

            return local_ip
    except Exception as e:
        logger.warning(f"Failed to detect local IP for target {target_ip}: {e}")
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
