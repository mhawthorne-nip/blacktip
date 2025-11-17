"""
Active network probing utilities for device reachability testing.

This module provides ARP-based and ICMP-based probing to actively verify
if devices are online, complementing passive ARP monitoring.
"""

import logging
from typing import Optional, Tuple
from datetime import datetime, timezone

try:
    from scapy.all import ARP, Ether, ICMP, IP, sr1, srp
    SCAPY_AVAILABLE = True
    
    # Suppress Scapy warnings about missing MAC addresses
    import logging as scapy_logging
    scapy_logging.getLogger("scapy.runtime").setLevel(scapy_logging.ERROR)
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)


class ActiveProber:
    """
    Active network prober using ARP and ICMP to verify device reachability.
    
    This class provides methods to actively probe devices on the network
    to determine if they are online, even when they are not generating
    spontaneous ARP traffic.
    """
    
    def __init__(self, interface: Optional[str] = None, timeout: float = 1.0, 
                 retry_count: int = 2, enable_icmp_fallback: bool = True):
        """
        Initialize the ActiveProber.
        
        Args:
            interface: Network interface to use for probing (None = default)
            timeout: Timeout in seconds for each probe attempt
            retry_count: Number of retry attempts for failed probes
            enable_icmp_fallback: Whether to fall back to ICMP if ARP fails
        """
        self.interface = interface
        self.timeout = timeout
        self.retry_count = retry_count
        self.enable_icmp_fallback = enable_icmp_fallback
        self.available = SCAPY_AVAILABLE
        
        if not SCAPY_AVAILABLE:
            logger.warning(
                "Scapy not available - active probing disabled. "
                "Install scapy to enable active probing: pip install scapy"
            )
    
    def probe_device(self, ip: str, mac: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Probe a device to check if it's online.
        
        First attempts ARP probing (layer 2, fast). If that fails and ICMP
        fallback is enabled, tries ICMP ping (layer 3, slower but more robust).
        
        Args:
            ip: IP address to probe
            mac: MAC address (optional, used for ARP probing optimization)
        
        Returns:
            Tuple of (is_online, method_used, error_message)
            - is_online: True if device responded, False otherwise
            - method_used: "arp", "icmp", or None if probe failed
            - error_message: Error description if probe failed, None otherwise
        """
        if not self.available:
            return False, None, "Scapy not available"
        
        # Try ARP probe first (fast, layer 2)
        is_online, error = self._arp_probe(ip, mac)
        if is_online:
            return True, "arp", None
        
        # If ARP failed and ICMP fallback is enabled, try ICMP
        if self.enable_icmp_fallback:
            logger.debug(f"ARP probe failed for {ip}, trying ICMP fallback")
            is_online, icmp_error = self._icmp_probe(ip)
            if is_online:
                return True, "icmp", None
            error = f"ARP failed: {error}, ICMP failed: {icmp_error}"
        
        return False, None, error
    
    def _arp_probe(self, ip: str, mac: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Perform ARP probe to check device reachability.
        
        Sends ARP request and waits for reply. Retries based on retry_count.
        
        Args:
            ip: IP address to probe
            mac: MAC address (optional, for directed ARP)
        
        Returns:
            Tuple of (is_online, error_message)
        """
        if not self.available:
            return False, "Scapy not available"
        
        try:
            # Build ARP request packet
            arp_request = ARP(pdst=ip)
            
            # Use broadcast Ethernet frame (or specific MAC if provided)
            dst_mac = mac if mac else "ff:ff:ff:ff:ff:ff"
            ether_frame = Ether(dst=dst_mac)
            packet = ether_frame / arp_request
            
            # Send packet and wait for response with retries
            for attempt in range(1, self.retry_count + 1):
                logger.debug(f"ARP probe attempt {attempt}/{self.retry_count} for {ip}")
                
                # srp returns (answered, unanswered) lists
                kwargs = {'timeout': self.timeout, 'verbose': False}
                if self.interface:
                    kwargs['iface'] = self.interface
                
                answered, _ = srp(packet, **kwargs)
                
                if answered:
                    # Device responded to ARP
                    logger.debug(f"ARP probe successful for {ip} on attempt {attempt}")
                    return True, None
            
            # All retries exhausted
            return False, f"No ARP response after {self.retry_count} attempts"
            
        except PermissionError as e:
            logger.warning(
                f"Permission denied for ARP probe of {ip}. "
                "Active probing requires root/administrator privileges. "
                f"Error: {e}"
            )
            return False, "Permission denied (requires root/admin)"
        except Exception as e:
            logger.error(f"Error during ARP probe of {ip}: {e}", exc_info=True)
            return False, f"ARP probe error: {str(e)}"
    
    def _icmp_probe(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Perform ICMP ping to check device reachability.
        
        Sends ICMP echo request and waits for reply. Retries based on retry_count.
        
        Args:
            ip: IP address to ping
        
        Returns:
            Tuple of (is_online, error_message)
        """
        if not self.available:
            return False, "Scapy not available"
        
        try:
            # Build ICMP echo request
            packet = IP(dst=ip) / ICMP()
            
            # Send packet and wait for response with retries
            for attempt in range(1, self.retry_count + 1):
                logger.debug(f"ICMP probe attempt {attempt}/{self.retry_count} for {ip}")
                
                kwargs = {'timeout': self.timeout, 'verbose': False}
                if self.interface:
                    kwargs['iface'] = self.interface
                
                response = sr1(packet, **kwargs)
                
                if response:
                    # Device responded to ping
                    logger.debug(f"ICMP probe successful for {ip} on attempt {attempt}")
                    return True, None
            
            # All retries exhausted
            return False, f"No ICMP response after {self.retry_count} attempts"
            
        except PermissionError as e:
            logger.warning(
                f"Permission denied for ICMP probe of {ip}. "
                "ICMP probing may require root/administrator privileges. "
                f"Error: {e}"
            )
            return False, "Permission denied (requires root/admin)"
        except Exception as e:
            logger.error(f"Error during ICMP probe of {ip}: {e}", exc_info=True)
            return False, f"ICMP probe error: {str(e)}"
    
    def probe_multiple(self, devices: list) -> dict:
        """
        Probe multiple devices and return their reachability status.
        
        Args:
            devices: List of dicts with 'ip' and optionally 'mac' keys
        
        Returns:
            Dict mapping IP addresses to probe results:
            {
                'ip_address': {
                    'online': bool,
                    'method': str or None,
                    'error': str or None,
                    'timestamp': ISO 8601 timestamp
                }
            }
        """
        results = {}
        
        for device in devices:
            ip = device.get('ip')
            mac = device.get('mac')
            
            if not ip:
                continue
            
            is_online, method, error = self.probe_device(ip, mac)
            
            results[ip] = {
                'online': is_online,
                'method': method,
                'error': error,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        return results
