"""DNS resolution utilities for blacktip"""
import socket
import time
from typing import Optional, Tuple
import logging

logger = logging.getLogger(__name__)


def reverse_dns_lookup(ip_address: str, timeout: float = 2.0) -> Tuple[Optional[str], Optional[float], bool]:
    """Perform reverse DNS lookup (PTR record) for an IP address

    Args:
        ip_address: IP address to look up
        timeout: DNS query timeout in seconds

    Returns:
        Tuple of (hostname, response_time_ms, forward_validates)
        - hostname: PTR record hostname or None if not found
        - response_time_ms: DNS query response time in milliseconds
        - forward_validates: Whether forward DNS lookup matches the IP
    """
    hostname = None
    response_time_ms = None
    forward_validates = False

    # Set socket timeout
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    try:
        # Perform reverse DNS lookup
        start_time = time.time()
        hostname = socket.gethostbyaddr(ip_address)[0]
        response_time_ms = (time.time() - start_time) * 1000

        logger.debug("Reverse DNS for {}: {} ({:.2f}ms)".format(
            ip_address, hostname, response_time_ms))

        # Validate with forward lookup
        if hostname:
            try:
                forward_ips = socket.gethostbyname_ex(hostname)[2]
                if ip_address in forward_ips:
                    forward_validates = True
                    logger.debug("Forward DNS validates for {}".format(hostname))
                else:
                    logger.debug("Forward DNS mismatch for {}: {} != {}".format(
                        hostname, ip_address, forward_ips))
            except (socket.herror, socket.gaierror) as e:
                logger.debug("Forward DNS lookup failed for {}: {}".format(hostname, e))

    except (socket.herror, socket.gaierror) as e:
        logger.debug("Reverse DNS lookup failed for {}: {}".format(ip_address, e))
    except socket.timeout:
        logger.debug("Reverse DNS lookup timed out for {}".format(ip_address))
    except Exception as e:
        logger.warning("Unexpected error during DNS lookup for {}: {}".format(ip_address, e))
    finally:
        # Restore original timeout
        socket.setdefaulttimeout(original_timeout)

    return hostname, response_time_ms, forward_validates


def batch_reverse_dns_lookup(ip_addresses: list, timeout: float = 2.0) -> dict:
    """Perform reverse DNS lookups for multiple IP addresses

    Args:
        ip_addresses: List of IP addresses
        timeout: DNS query timeout per IP in seconds

    Returns:
        Dictionary mapping IP addresses to (hostname, response_time_ms, forward_validates) tuples
    """
    results = {}

    for ip_address in ip_addresses:
        hostname, response_time_ms, forward_validates = reverse_dns_lookup(ip_address, timeout)
        results[ip_address] = {
            'hostname': hostname,
            'response_time_ms': response_time_ms,
            'forward_validates': forward_validates
        }

    return results
