"""
Tests for active probing functionality
"""

import unittest
from unittest.mock import MagicMock, patch
from src.blacktip.utils.active_probe import ActiveProber


class TestActiveProber(unittest.TestCase):
    """Test cases for the ActiveProber class"""
    
    def test_initialization(self):
        """Test ActiveProber initialization with default parameters"""
        prober = ActiveProber()
        
        self.assertEqual(prober.timeout, 1.0)
        self.assertEqual(prober.retry_count, 2)
        self.assertTrue(prober.enable_icmp_fallback)
        self.assertIsNone(prober.interface)
    
    def test_initialization_custom_params(self):
        """Test ActiveProber initialization with custom parameters"""
        prober = ActiveProber(
            interface="eth0",
            timeout=2.5,
            retry_count=3,
            enable_icmp_fallback=False
        )
        
        self.assertEqual(prober.interface, "eth0")
        self.assertEqual(prober.timeout, 2.5)
        self.assertEqual(prober.retry_count, 3)
        self.assertFalse(prober.enable_icmp_fallback)
    
    def test_scapy_unavailable(self):
        """Test graceful handling when Scapy is not available"""
        # This test verifies the module imports even without scapy
        # The actual behavior is tested in integration tests
        with patch('src.blacktip.utils.active_probe.SCAPY_AVAILABLE', False):
            prober = ActiveProber()
            self.assertFalse(prober.available)
            
            # Should return failure when scapy unavailable
            is_online, method, error = prober.probe_device("192.168.1.1")
            self.assertFalse(is_online)
            self.assertIsNone(method)
            self.assertEqual(error, "Scapy not available")
    
    def test_probe_device_no_scapy(self):
        """Test probe_device when Scapy is unavailable"""
        prober = ActiveProber()
        prober.available = False
        
        is_online, method, error = prober.probe_device("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        
        self.assertFalse(is_online)
        self.assertIsNone(method)
        self.assertIn("Scapy", error)
    
    @patch('src.blacktip.utils.active_probe.srp')
    def test_arp_probe_success(self, mock_srp):
        """Test successful ARP probe"""
        # Mock successful ARP response
        mock_srp.return_value = ([MagicMock()], [])
        
        prober = ActiveProber()
        if not prober.available:
            self.skipTest("Scapy not available")
        
        is_online, error = prober._arp_probe("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        
        self.assertTrue(is_online)
        self.assertIsNone(error)
    
    @patch('src.blacktip.utils.active_probe.srp')
    def test_arp_probe_failure(self, mock_srp):
        """Test failed ARP probe (no response)"""
        # Mock no ARP response
        mock_srp.return_value = ([], [])
        
        prober = ActiveProber(retry_count=1)
        if not prober.available:
            self.skipTest("Scapy not available")
        
        is_online, error = prober._arp_probe("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        
        self.assertFalse(is_online)
        self.assertIsNotNone(error)
    
    @patch('src.blacktip.utils.active_probe.sr1')
    def test_icmp_probe_success(self, mock_sr1):
        """Test successful ICMP probe"""
        # Mock successful ICMP response
        mock_sr1.return_value = MagicMock()
        
        prober = ActiveProber()
        if not prober.available:
            self.skipTest("Scapy not available")
        
        is_online, error = prober._icmp_probe("192.168.1.1")
        
        self.assertTrue(is_online)
        self.assertIsNone(error)
    
    @patch('src.blacktip.utils.active_probe.sr1')
    def test_icmp_probe_failure(self, mock_sr1):
        """Test failed ICMP probe (no response)"""
        # Mock no ICMP response
        mock_sr1.return_value = None
        
        prober = ActiveProber(retry_count=1)
        if not prober.available:
            self.skipTest("Scapy not available")
        
        is_online, error = prober._icmp_probe("192.168.1.1")
        
        self.assertFalse(is_online)
        self.assertIsNotNone(error)
    
    @patch('src.blacktip.utils.active_probe.srp')
    @patch('src.blacktip.utils.active_probe.sr1')
    def test_probe_device_icmp_fallback(self, mock_sr1, mock_srp):
        """Test ICMP fallback when ARP fails"""
        # Mock ARP failure and ICMP success
        mock_srp.return_value = ([], [])
        mock_sr1.return_value = MagicMock()
        
        prober = ActiveProber(retry_count=1, enable_icmp_fallback=True)
        if not prober.available:
            self.skipTest("Scapy not available")
        
        is_online, method, error = prober.probe_device("192.168.1.1")
        
        self.assertTrue(is_online)
        self.assertEqual(method, "icmp")
        self.assertIsNone(error)
    
    @patch('src.blacktip.utils.active_probe.srp')
    def test_probe_device_no_icmp_fallback(self, mock_srp):
        """Test no ICMP fallback when disabled"""
        # Mock ARP failure
        mock_srp.return_value = ([], [])
        
        prober = ActiveProber(retry_count=1, enable_icmp_fallback=False)
        if not prober.available:
            self.skipTest("Scapy not available")
        
        is_online, method, error = prober.probe_device("192.168.1.1")
        
        self.assertFalse(is_online)
        self.assertIsNone(method)
        self.assertIsNotNone(error)
    
    def test_probe_multiple(self):
        """Test probing multiple devices"""
        prober = ActiveProber()
        prober.available = False  # Force unavailable for this test
        
        devices = [
            {'ip': '192.168.1.1', 'mac': 'aa:bb:cc:dd:ee:ff'},
            {'ip': '192.168.1.2', 'mac': 'ff:ee:dd:cc:bb:aa'},
        ]
        
        results = prober.probe_multiple(devices)
        
        self.assertEqual(len(results), 2)
        self.assertIn('192.168.1.1', results)
        self.assertIn('192.168.1.2', results)
        self.assertFalse(results['192.168.1.1']['online'])
        self.assertFalse(results['192.168.1.2']['online'])


if __name__ == '__main__':
    unittest.main()
