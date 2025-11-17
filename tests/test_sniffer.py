"""Tests for sniffer module, particularly address validation"""

import pytest
from blacktip.utils.sniffer import BlacktipSniffer
from blacktip.exceptions import BlacktipException
from unittest.mock import Mock


class TestScubAddress:
    """Test the scrub_address method for IP and MAC validation"""

    def setup_method(self):
        """Create sniffer instance for each test"""
        self.sniffer = BlacktipSniffer()

    def test_valid_ip_addresses(self):
        """Test that valid IP addresses are accepted"""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "1.1.1.1",
            "255.255.255.254",
        ]
        for ip in valid_ips:
            result = self.sniffer.scrub_address("ip", ip)
            assert result == ip, "Valid IP {} should be accepted".format(ip)

    def test_reject_reserved_ip_addresses(self):
        """Test that reserved IP addresses are rejected"""
        reserved_ips = [
            "0.0.0.0",          # Reserved "this network"
            "255.255.255.255",  # Broadcast address
        ]
        for ip in reserved_ips:
            result = self.sniffer.scrub_address("ip", ip)
            assert result == "", "Reserved IP {} should be rejected".format(ip)

    def test_invalid_ip_addresses(self):
        """Test that invalid IP addresses are rejected"""
        invalid_ips = [
            "",
            "256.1.1.1",        # Octet too large
            "192.168.1",        # Too few octets
            "192.168.1.1.1",    # Too many octets
            "abc.def.ghi.jkl",  # Non-numeric
            "192.168.-1.1",     # Negative number
            "192.168.1.1.com",  # Extra characters
        ]
        for ip in invalid_ips:
            result = self.sniffer.scrub_address("ip", ip)
            assert result == "", "Invalid IP {} should be rejected".format(ip)

    def test_valid_mac_addresses(self):
        """Test that valid MAC addresses are accepted"""
        valid_macs = [
            "aa:bb:cc:dd:ee:ff",
            "00:11:22:33:44:55",
            "AA:BB:CC:DD:EE:FF",  # Should be lowercased
            "12:34:56:78:9a:bc",
        ]
        expected = [
            "aa:bb:cc:dd:ee:ff",
            "00:11:22:33:44:55",
            "aa:bb:cc:dd:ee:ff",  # Lowercased
            "12:34:56:78:9a:bc",
        ]
        for mac, exp in zip(valid_macs, expected):
            result = self.sniffer.scrub_address("hw", mac)
            assert result == exp, "Valid MAC {} should be accepted as {}".format(mac, exp)

    def test_invalid_mac_addresses(self):
        """Test that invalid MAC addresses are rejected"""
        invalid_macs = [
            "",
            "aa:bb:cc:dd:ee",      # Too short
            "aa:bb:cc:dd:ee:ff:00", # Too long
            "gg:hh:ii:jj:kk:ll",   # Invalid hex chars
            "aa-bb-cc-dd-ee-ff",   # Wrong separator
            "aabbccddeeff",        # No separators
        ]
        for mac in invalid_macs:
            result = self.sniffer.scrub_address("hw", mac)
            assert result == "", "Invalid MAC {} should be rejected".format(mac)

    def test_unsupported_address_type(self):
        """Test that unsupported address types raise exception"""
        with pytest.raises(BlacktipException):
            self.sniffer.scrub_address("ipv6", "::1")


class TestGetHwVendor:
    """Test hardware vendor lookup with caching"""

    def setup_method(self):
        """Create sniffer instance for each test"""
        self.sniffer = BlacktipSniffer()

    def test_empty_mac_returns_unknown(self):
        """Test that empty MAC returns Unknown"""
        assert self.sniffer.get_hw_vendor("") == "Unknown"
        assert self.sniffer.get_hw_vendor(None) == "Unknown"

    def test_zero_mac_returns_unknown(self):
        """Test that all-zero MAC returns Unknown"""
        assert self.sniffer.get_hw_vendor("00:00:00:00:00:00") == "Unknown"

    def test_vendor_caching(self):
        """Test that vendor lookups are cached"""
        mac = "aa:bb:cc:dd:ee:ff"

        # First lookup
        vendor1 = self.sniffer.get_hw_vendor(mac)

        # Second lookup should be from cache
        vendor2 = self.sniffer.get_hw_vendor(mac)

        assert vendor1 == vendor2, "Cached vendor should match"
        assert mac in self.sniffer._vendor_cache, "MAC should be in cache"

class TestProcessPacket:
    """Test packet processing with reserved IP address rejection"""

    def setup_method(self):
        """Create sniffer instance for each test"""
        self.sniffer = BlacktipSniffer()
        self.mock_db = Mock()

    def test_reject_packet_with_reserved_ip_0_0_0_0(self):
        """Test that packets with 0.0.0.0 are rejected"""
        packet = {
            "src": {
                "ip": "0.0.0.0",
                "hw": "aa:bb:cc:dd:ee:ff"
            },
            "dst": {
                "ip": "192.168.1.1",
                "hw": "00:11:22:33:44:55"
            },
            "op": "request"
        }
        
        result = self.sniffer.process_packet(packet, self.mock_db)
        assert result is None, "Packet with 0.0.0.0 should be rejected"
        self.mock_db.upsert_device.assert_not_called()

    def test_reject_packet_with_broadcast_ip(self):
        """Test that packets with 255.255.255.255 are rejected"""
        packet = {
            "src": {
                "ip": "255.255.255.255",
                "hw": "aa:bb:cc:dd:ee:ff"
            },
            "dst": {
                "ip": "192.168.1.1",
                "hw": "00:11:22:33:44:55"
            },
            "op": "request"
        }
        
        result = self.sniffer.process_packet(packet, self.mock_db)
        assert result is None, "Packet with 255.255.255.255 should be rejected"
        self.mock_db.upsert_device.assert_not_called()

    def test_accept_valid_packet(self):
        """Test that packets with valid IPs are processed"""
        packet = {
            "src": {
                "ip": "192.168.1.100",
                "hw": "aa:bb:cc:dd:ee:ff"
            },
            "dst": {
                "ip": "192.168.1.1",
                "hw": "00:11:22:33:44:55"
            },
            "op": "request"
        }
        
        # Mock the database responses
        self.mock_db.check_ip_conflict.return_value = None
        self.mock_db.upsert_device.return_value = (1, True, True)
        
        result = self.sniffer.process_packet(packet, self.mock_db)
        assert result is not None, "Valid packet should be processed"
        self.mock_db.upsert_device.assert_called_once()