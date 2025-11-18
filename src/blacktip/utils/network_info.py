"""
Network information collector for internet connection details.

Collects public IP, ISP, geolocation, and reverse DNS information.
"""

import logging
import socket
import requests
from typing import Dict, Optional
from datetime import datetime

_logger = logging.getLogger(__name__)


class NetworkInfoCollector:
    """Collector for internet connection and network information"""
    
    def __init__(self):
        """Initialize network info collector"""
        self._timeout = 10  # seconds
    
    def get_reverse_dns(self, ip_address: str) -> Optional[str]:
        """Get reverse DNS hostname for an IP address
        
        Args:
            ip_address: Public IP address
            
        Returns:
            Hostname from reverse DNS lookup, or None if lookup fails
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            _logger.debug("Reverse DNS for {}: {}".format(ip_address, hostname))
            return hostname
        except socket.herror as e:
            _logger.debug("Reverse DNS lookup failed for {}: {}".format(ip_address, e))
            return None
        except socket.gaierror as e:
            _logger.debug("Reverse DNS lookup error for {}: {}".format(ip_address, e))
            return None
        except Exception as e:
            _logger.warning("Unexpected error in reverse DNS lookup: {}".format(e))
            return None
    
    def get_geolocation_ipapi(self, ip_address: str) -> Optional[Dict]:
        """Get geolocation info using ip-api.com (free, no key required)
        
        Args:
            ip_address: Public IP address
            
        Returns:
            Dictionary with location data, or None if lookup fails
        """
        try:
            # ip-api.com free tier: 45 requests/minute
            url = "http://ip-api.com/json/{}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as".format(ip_address)
            
            response = requests.get(url, timeout=self._timeout)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('status') == 'success':
                _logger.debug("Geolocation lookup successful for {}".format(ip_address))
                return {
                    'country': data.get('country'),
                    'country_code': data.get('countryCode'),
                    'region': data.get('regionName'),
                    'region_code': data.get('region'),
                    'city': data.get('city'),
                    'zip_code': data.get('zip'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'timezone': data.get('timezone'),
                    'isp_name': data.get('isp'),
                    'org': data.get('org'),
                    'as': data.get('as')
                }
            else:
                _logger.warning("Geolocation lookup failed: {}".format(data.get('message', 'Unknown error')))
                return None
                
        except requests.RequestException as e:
            _logger.warning("Geolocation API request failed: {}".format(e))
            return None
        except Exception as e:
            _logger.error("Unexpected error in geolocation lookup: {}".format(e))
            return None
    
    def collect_network_info(self, public_ip: Optional[str] = None, 
                            isp_name: Optional[str] = None) -> Dict:
        """Collect comprehensive network information
        
        Args:
            public_ip: Public IP address (will be auto-detected if not provided)
            isp_name: ISP name from speedtest (optional, will use geolocation API if not provided)
            
        Returns:
            Dictionary with network information
        """
        _logger.info("Collecting network information...")
        
        network_info = {}
        
        # Get public IP if not provided
        if not public_ip:
            public_ip = self.get_public_ip()
        
        if not public_ip:
            _logger.error("Could not determine public IP address")
            return network_info
        
        network_info['public_ip'] = public_ip
        
        # Get reverse DNS hostname
        hostname = self.get_reverse_dns(public_ip)
        if hostname:
            network_info['hostname'] = hostname
        
        # Get geolocation info
        geo_info = self.get_geolocation_ipapi(public_ip)
        if geo_info:
            network_info.update({
                'city': geo_info.get('city'),
                'region': geo_info.get('region'),
                'country': geo_info.get('country'),
                'timezone': geo_info.get('timezone'),
                'latitude': geo_info.get('latitude'),
                'longitude': geo_info.get('longitude'),
                'isp_name': isp_name or geo_info.get('isp_name'),  # Prefer speedtest ISP name
            })
        else:
            # Use provided ISP name if geolocation failed
            if isp_name:
                network_info['isp_name'] = isp_name
        
        _logger.info("Network info collected: IP={}, ISP={}, Location={}, {}".format(
            public_ip,
            network_info.get('isp_name', 'Unknown'),
            network_info.get('city', 'Unknown'),
            network_info.get('region', 'Unknown')
        ))
        
        return network_info
    
    def get_public_ip(self) -> Optional[str]:
        """Get public IP address using external service
        
        Returns:
            Public IP address string, or None if lookup fails
        """
        # Try multiple services for reliability
        services = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://ifconfig.me/ip',
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                response.raise_for_status()
                ip = response.text.strip()
                _logger.debug("Public IP from {}: {}".format(service, ip))
                return ip
            except Exception as e:
                _logger.debug("Failed to get IP from {}: {}".format(service, e))
                continue
        
        _logger.error("Could not determine public IP from any service")
        return None
