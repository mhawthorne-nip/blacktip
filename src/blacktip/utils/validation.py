"""Input validation utilities for IP addresses, MAC addresses, and other inputs"""

import re
from typing import Optional, Tuple
import validators


def validate_ip_address(ip_address: str) -> Tuple[bool, Optional[str]]:
    """Validate an IPv4 address

    Args:
        ip_address: IP address string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not ip_address:
        return False, "IP address cannot be empty"

    # Basic format check
    if not isinstance(ip_address, str):
        return False, "IP address must be a string"

    # Use validators library for robust validation
    try:
        is_valid = validators.ipv4(ip_address)
        if is_valid:
            return True, None
        else:
            return False, "Invalid IPv4 address format"
    except Exception as e:
        return False, "IP validation error: {}".format(e)


def validate_mac_address(mac_address: str) -> Tuple[bool, Optional[str]]:
    """Validate a MAC address

    Args:
        mac_address: MAC address string to validate (XX:XX:XX:XX:XX:XX format)

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not mac_address:
        return False, "MAC address cannot be empty"

    if not isinstance(mac_address, str):
        return False, "MAC address must be a string"

    # Standard MAC address format: XX:XX:XX:XX:XX:XX (hexadecimal with colons)
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')

    if not mac_pattern.match(mac_address):
        return False, "Invalid MAC address format. Expected XX:XX:XX:XX:XX:XX"

    return True, None


def sanitize_ip_address(ip_address: str) -> str:
    """Sanitize and validate IP address, removing any invalid characters

    Args:
        ip_address: IP address string to sanitize

    Returns:
        Sanitized IP address or empty string if invalid
    """
    if not ip_address:
        return ""

    # Remove everything except dots and digits
    sanitized = "".join(c for c in str(ip_address) if c in ".0123456789")

    # Validate the sanitized IP
    is_valid, _ = validate_ip_address(sanitized)
    if is_valid:
        return sanitized
    return ""


def sanitize_mac_address(mac_address: str) -> str:
    """Sanitize and validate MAC address, removing any invalid characters

    Args:
        mac_address: MAC address string to sanitize

    Returns:
        Sanitized MAC address or empty string if invalid
    """
    if not mac_address:
        return ""

    # Remove everything except colons and hex digits, convert to lowercase
    sanitized = "".join(
        c for c in str(mac_address).lower()
        if c in ":0123456789abcdef"
    )

    # Validate the sanitized MAC
    is_valid, _ = validate_mac_address(sanitized)
    if is_valid:
        return sanitized
    return ""


def validate_username(username: str) -> Tuple[bool, Optional[str]]:
    """Validate a Unix username for use with sudo

    Args:
        username: Username to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not username:
        return False, "Username cannot be empty"

    if not isinstance(username, str):
        return False, "Username must be a string"

    # Unix username requirements: alphanumeric, underscore, hyphen, max 32 chars
    # Must start with letter or underscore
    if len(username) > 32:
        return False, "Username too long (max 32 characters)"

    if not re.match(r'^[a-z_][a-z0-9_-]*$', username):
        return False, "Invalid username format. Must start with letter/underscore and contain only alphanumeric, underscore, or hyphen"

    return True, None


def validate_command_template(command_template: str) -> Tuple[bool, list]:
    """Validate a command template for dangerous patterns

    Args:
        command_template: Command template string with {IP}, {HW}, {TS} placeholders

    Returns:
        Tuple of (is_safe, list of warnings)
    """
    if not command_template:
        return True, []

    warnings = []
    dangerous_patterns = [
        (';', 'contains semicolon (command chaining)'),
        ('&&', 'contains && (command chaining)'),
        ('||', 'contains || (command chaining)'),
        ('`', 'contains backticks (command substitution)'),
        ('$(', 'contains $( (command substitution)'),
        ('|', 'contains pipe (may chain commands)'),
        ('>', 'contains redirect'),
        ('<', 'contains redirect'),
    ]

    # Critical patterns that make it unsafe
    critical_patterns = ['$(', '`']

    for pattern, message in dangerous_patterns:
        if pattern in command_template:
            # Check if it's not part of the template variables
            if pattern not in ['{IP}', '{HW}', '{TS}']:
                warnings.append(message)

    # Check for critical issues
    is_safe = not any(pattern in command_template for pattern in critical_patterns)

    return is_safe, warnings


def validate_interface_name(interface: str) -> Tuple[bool, Optional[str]]:
    """Validate a network interface name

    Args:
        interface: Network interface name (e.g., eth0, wlan0)

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not interface:
        return False, "Interface name cannot be empty"

    if not isinstance(interface, str):
        return False, "Interface name must be a string"

    # Linux interface names: alphanumeric, max 15 chars, no special chars except period
    if len(interface) > 15:
        return False, "Interface name too long (max 15 characters)"

    if not re.match(r'^[a-zA-Z0-9.]+$', interface):
        return False, "Invalid interface name format"

    return True, None


def validate_port(port: int) -> Tuple[bool, Optional[str]]:
    """Validate a network port number

    Args:
        port: Port number to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(port, int):
        return False, "Port must be an integer"

    if port < 1 or port > 65535:
        return False, "Port must be between 1 and 65535"

    return True, None
