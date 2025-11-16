"""Geolocation and ASN lookup utilities for blacktip"""
import logging
import ipaddress
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class GeoLocator:
    """IP geolocation and ASN lookup"""

    @staticmethod
    def is_private_ip(ip_address: str) -> bool:
        """Check if an IP address is private/local

        Args:
            ip_address: IP address to check

        Returns:
            True if IP is private, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    @staticmethod
    def lookup_ip_geolocation(ip_address: str, use_api: bool = False) -> Optional[Dict]:
        """Lookup geolocation information for an IP address

        Args:
            ip_address: IP address to lookup
            use_api: Whether to use external API (requires network access)

        Returns:
            Dictionary with geolocation data or None if not available
            Keys: country_code, country_name, region, city, latitude, longitude,
                  asn, asn_org, isp, is_proxy, is_vpn, is_tor, threat_score
        """
        # Check if private IP
        if GeoLocator.is_private_ip(ip_address):
            logger.debug("IP {} is private - no geolocation available".format(ip_address))
            return {
                'country_code': 'LOCAL',
                'country_name': 'Private Network',
                'region': None,
                'city': None,
                'latitude': None,
                'longitude': None,
                'asn': None,
                'asn_org': None,
                'isp': 'Local Network',
                'is_proxy': 0,
                'is_vpn': 0,
                'is_tor': 0,
                'threat_score': 0
            }

        # If API usage is disabled, return None for public IPs
        if not use_api:
            logger.debug("Geolocation API disabled - skipping lookup for {}".format(ip_address))
            return None

        # Use ip-api.com free service (no API key needed, but rate limited)
        # For production, consider using paid services or local GeoIP databases
        try:
            import urllib.request
            import json

            url = "http://ip-api.com/json/{}?fields=status,message,country,countryCode,region,city,lat,lon,isp,as,proxy,hosting".format(ip_address)

            with urllib.request.urlopen(url, timeout=5) as response:
                data = json.loads(response.read().decode())

                if data.get('status') == 'success':
                    # Parse ASN (format: "AS15169 Google LLC")
                    asn_string = data.get('as', '')
                    asn = None
                    asn_org = None
                    if asn_string:
                        parts = asn_string.split(' ', 1)
                        if parts[0].startswith('AS'):
                            try:
                                asn = int(parts[0][2:])
                                asn_org = parts[1] if len(parts) > 1 else None
                            except ValueError:
                                pass

                    geo_data = {
                        'country_code': data.get('countryCode'),
                        'country_name': data.get('country'),
                        'region': data.get('region'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'asn': asn,
                        'asn_org': asn_org,
                        'isp': data.get('isp'),
                        'is_proxy': 1 if data.get('proxy') else 0,
                        'is_vpn': 0,  # Would need enhanced service
                        'is_tor': 0,  # Would need enhanced service
                        'threat_score': 0  # Would need threat intelligence service
                    }

                    logger.debug("Geolocation for {}: {}, {} ({})".format(
                        ip_address,
                        geo_data['city'],
                        geo_data['country_name'],
                        geo_data['isp']
                    ))

                    return geo_data
                else:
                    logger.warning("Geolocation lookup failed for {}: {}".format(
                        ip_address, data.get('message')))
                    return None

        except Exception as e:
            logger.warning("Geolocation lookup error for {}: {}".format(ip_address, e))
            return None

    @staticmethod
    def batch_lookup_geolocation(ip_addresses: list, use_api: bool = False) -> dict:
        """Lookup geolocation for multiple IP addresses

        Args:
            ip_addresses: List of IP addresses
            use_api: Whether to use external API

        Returns:
            Dictionary mapping IP addresses to geolocation data
        """
        results = {}

        for ip_address in ip_addresses:
            geo_data = GeoLocator.lookup_ip_geolocation(ip_address, use_api)
            if geo_data:
                results[ip_address] = geo_data

        return results


def is_private_network(ip_address: str) -> bool:
    """Convenience function to check if IP is in private address space

    Args:
        ip_address: IP address to check

    Returns:
        True if private, False if public
    """
    return GeoLocator.is_private_ip(ip_address)
