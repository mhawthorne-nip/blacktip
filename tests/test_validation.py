"""Tests for validation utilities"""
import pytest
from blacktip.utils.validation import (
    validate_ip_address,
    validate_mac_address,
    sanitize_ip_address,
    sanitize_mac_address,
    validate_username,
    validate_command_template,
    validate_interface_name,
    validate_port,
)


class TestIPValidation:
    """Test IP address validation"""

    def test_valid_ip_addresses(self):
        """Test valid IP addresses"""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "255.255.255.255",
            "0.0.0.0",
        ]
        for ip in valid_ips:
            is_valid, error = validate_ip_address(ip)
            assert is_valid, "IP {} should be valid: {}".format(ip, error)
            assert error is None

    def test_invalid_ip_addresses(self):
        """Test invalid IP addresses"""
        invalid_ips = [
            "256.1.1.1",  # Out of range
            "192.168.1",  # Incomplete
            "192.168.1.1.1",  # Too many octets
            "abc.def.ghi.jkl",  # Not numeric
            "",  # Empty
            "192.168.-1.1",  # Negative
        ]
        for ip in invalid_ips:
            is_valid, error = validate_ip_address(ip)
            assert not is_valid, "IP {} should be invalid".format(ip)
            assert error is not None

    def test_sanitize_ip_address(self):
        """Test IP address sanitization"""
        assert sanitize_ip_address("192.168.1.1") == "192.168.1.1"
        assert sanitize_ip_address("192.168.1.1abc") == "192.168.1.1"
        assert sanitize_ip_address("abc192.168.1.1") == "192.168.1.1"
        assert sanitize_ip_address("256.1.1.1") == ""  # Invalid after sanitization
        assert sanitize_ip_address("") == ""


class TestMACValidation:
    """Test MAC address validation"""

    def test_valid_mac_addresses(self):
        """Test valid MAC addresses"""
        valid_macs = [
            "00:11:22:33:44:55",
            "AA:BB:CC:DD:EE:FF",
            "aa:bb:cc:dd:ee:ff",
            "01:23:45:67:89:AB",
        ]
        for mac in valid_macs:
            is_valid, error = validate_mac_address(mac)
            assert is_valid, "MAC {} should be valid: {}".format(mac, error)
            assert error is None

    def test_invalid_mac_addresses(self):
        """Test invalid MAC addresses"""
        invalid_macs = [
            "00:11:22:33:44",  # Incomplete
            "00:11:22:33:44:55:66",  # Too many octets
            "00-11-22-33-44-55",  # Wrong separator
            "GG:HH:II:JJ:KK:LL",  # Invalid hex
            "",  # Empty
            "00:11:22:33:44:5",  # Incomplete octet
        ]
        for mac in invalid_macs:
            is_valid, error = validate_mac_address(mac)
            assert not is_valid, "MAC {} should be invalid".format(mac)
            assert error is not None

    def test_sanitize_mac_address(self):
        """Test MAC address sanitization"""
        assert sanitize_mac_address("00:11:22:33:44:55") == "00:11:22:33:44:55"
        assert sanitize_mac_address("00:11:22:33:44:55ABC") == ""  # Invalid after sanitization
        assert sanitize_mac_address("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"  # Lowercase
        assert sanitize_mac_address("") == ""


class TestUsernameValidation:
    """Test username validation"""

    def test_valid_usernames(self):
        """Test valid usernames"""
        valid_usernames = [
            "nobody",
            "root",
            "user123",
            "test_user",
            "test-user",
            "_test",
        ]
        for username in valid_usernames:
            is_valid, error = validate_username(username)
            assert is_valid, "Username {} should be valid: {}".format(username, error)
            assert error is None

    def test_invalid_usernames(self):
        """Test invalid usernames"""
        invalid_usernames = [
            "123user",  # Starts with number
            "user name",  # Contains space
            "user@host",  # Invalid character
            "",  # Empty
            "a" * 33,  # Too long
            "User",  # Uppercase (Unix usernames are lowercase)
        ]
        for username in invalid_usernames:
            is_valid, error = validate_username(username)
            assert not is_valid, "Username {} should be invalid".format(username)
            assert error is not None


class TestCommandValidation:
    """Test command template validation"""

    def test_safe_commands(self):
        """Test safe command templates"""
        safe_commands = [
            "nmap -sV {IP}",
            "ping -c 4 {IP}",
            "echo {HW}",
        ]
        for cmd in safe_commands:
            is_safe, warnings = validate_command_template(cmd)
            assert is_safe, "Command {} should be safe".format(cmd)

    def test_unsafe_commands(self):
        """Test unsafe command templates"""
        unsafe_commands = [
            "rm -rf / `whoami`",  # Backticks
            "echo $$(whoami)",  # Command substitution
        ]
        for cmd in unsafe_commands:
            is_safe, warnings = validate_command_template(cmd)
            assert not is_safe, "Command {} should be unsafe".format(cmd)
            assert len(warnings) > 0

    def test_warning_commands(self):
        """Test commands that generate warnings but may be safe"""
        warning_commands = [
            "nmap -sV {IP} | grep open",  # Pipe
            "nmap -sV {IP} > output.txt",  # Redirect
        ]
        for cmd in warning_commands:
            is_safe, warnings = validate_command_template(cmd)
            # These may be safe but should generate warnings
            assert len(warnings) > 0


class TestInterfaceValidation:
    """Test network interface validation"""

    def test_valid_interfaces(self):
        """Test valid interface names"""
        valid_interfaces = [
            "eth0",
            "wlan0",
            "lo",
            "enp0s3",
            "wlp2s0",
        ]
        for iface in valid_interfaces:
            is_valid, error = validate_interface_name(iface)
            assert is_valid, "Interface {} should be valid: {}".format(iface, error)
            assert error is None

    def test_invalid_interfaces(self):
        """Test invalid interface names"""
        invalid_interfaces = [
            "",  # Empty
            "eth0!" # Invalid character
            "a" * 16,  # Too long
        ]
        for iface in invalid_interfaces:
            is_valid, error = validate_interface_name(iface)
            assert not is_valid, "Interface {} should be invalid".format(iface)
            assert error is not None


class TestPortValidation:
    """Test port number validation"""

    def test_valid_ports(self):
        """Test valid port numbers"""
        valid_ports = [1, 80, 443, 8080, 65535]
        for port in valid_ports:
            is_valid, error = validate_port(port)
            assert is_valid, "Port {} should be valid: {}".format(port, error)
            assert error is None

    def test_invalid_ports(self):
        """Test invalid port numbers"""
        invalid_ports = [0, -1, 65536, 100000, "80"]
        for port in invalid_ports:
            is_valid, error = validate_port(port)
            assert not is_valid, "Port {} should be invalid".format(port)
            assert error is not None
