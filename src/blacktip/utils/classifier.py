"""Device classification utilities for blacktip"""
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class DeviceClassifier:
    """Classify devices based on network characteristics"""

    # Port-based device type patterns
    PORT_PATTERNS = {
        'router': [53, 80, 443, 23],  # DNS, HTTP/HTTPS, Telnet
        'printer': [9100, 515, 631, 161],  # JetDirect, LPD, IPP, SNMP
        'nas': [139, 445, 548, 2049, 5000],  # SMB, AFP, NFS, Synology
        'camera': [554, 8080, 80, 443],  # RTSP, Web interfaces
        'iot': [1883, 8883, 5683],  # MQTT, CoAP
        'server': [80, 443, 22, 3306, 5432, 27017],  # Web, SSH, databases
        'workstation': [135, 139, 445, 3389],  # Windows services, RDP
        'mobile': [62078],  # Apple mobile sync
        'media_device': [8200, 32469, 49152],  # Plex, other media servers
        'smart_tv': [8001, 8080, 9080],  # Samsung, LG, etc.
        'game_console': [3074, 3478, 3479],  # Xbox, PlayStation
    }

    # Vendor-based device type patterns
    VENDOR_PATTERNS = {
        'router': ['cisco', 'netgear', 'tp-link', 'asus', 'linksys', 'ubiquiti', 'mikrotik'],
        'printer': ['hp', 'canon', 'epson', 'brother', 'xerox', 'samsung', 'lexmark'],
        'mobile': ['apple', 'samsung', 'huawei', 'xiaomi', 'google', 'motorola', 'lg'],
        'iot': ['nest', 'ring', 'ecobee', 'philips hue', 'wemo', 'sonos'],
        'nas': ['synology', 'qnap', 'netgear', 'western digital'],
        'camera': ['axis', 'hikvision', 'dahua', 'vivotek', 'foscam'],
    }

    # OS-based device type patterns
    OS_PATTERNS = {
        'server': ['linux', 'ubuntu', 'debian', 'centos', 'red hat', 'windows server'],
        'workstation': ['windows 10', 'windows 11', 'windows 7', 'macos', 'mac os x'],
        'mobile': ['ios', 'android', 'iphone', 'ipad'],
        'router': ['cisco ios', 'junos', 'mikrotik', 'openwrt', 'dd-wrt'],
        'nas': ['freenas', 'truenas', 'dsm', 'qts'],
    }

    # Service-based patterns (from nmap service detection)
    SERVICE_PATTERNS = {
        'database': ['mysql', 'postgresql', 'mongodb', 'redis', 'mariadb', 'mssql'],
        'web_server': ['apache', 'nginx', 'iis', 'lighttpd'],
        'mail_server': ['smtp', 'pop3', 'imap', 'exchange'],
        'file_server': ['ftp', 'sftp', 'smb', 'nfs'],
    }

    @staticmethod
    def classify_device(device_data: Dict) -> Dict:
        """Classify a device based on available characteristics

        Args:
            device_data: Dictionary containing device information:
                - vendor: MAC vendor (optional)
                - os_name: Detected OS (optional)
                - ports: List of port dictionaries with service info (optional)
                - netbios_name: NetBIOS computer name (optional)
                - hostname: DNS hostname (optional)

        Returns:
            Dictionary with classification:
                - device_type: Primary device type
                - device_category: Broader category
                - manufacturer: Detected manufacturer (if any)
                - model: Detected model (if any)
                - confidence_score: 0.0-1.0 confidence
                - classification_method: How it was classified
        """
        classification = {
            'device_type': 'unknown',
            'device_category': 'unknown',
            'manufacturer': None,
            'model': None,
            'confidence_score': 0.0,
            'classification_method': 'none'
        }

        scores = {}  # Type -> score mapping
        methods = []  # Classification methods used

        # Extract data
        vendor = (device_data.get('vendor') or '').lower()
        os_name = (device_data.get('os_name') or '').lower()
        ports = device_data.get('ports', [])
        hostname = (device_data.get('hostname') or '').lower()
        netbios_name = (device_data.get('netbios_name') or '').lower()

        # Classify based on MAC vendor
        if vendor:
            for device_type, vendor_patterns in DeviceClassifier.VENDOR_PATTERNS.items():
                for pattern in vendor_patterns:
                    if pattern in vendor:
                        scores[device_type] = scores.get(device_type, 0) + 0.3
                        methods.append('vendor')
                        classification['manufacturer'] = vendor
                        break

        # Classify based on OS
        if os_name:
            for device_type, os_patterns in DeviceClassifier.OS_PATTERNS.items():
                for pattern in os_patterns:
                    if pattern in os_name:
                        scores[device_type] = scores.get(device_type, 0) + 0.4
                        methods.append('os')
                        break

        # Classify based on open ports
        if ports:
            open_port_numbers = [p.get('port') for p in ports if p.get('state') == 'open']
            service_names = [p.get('service_name', '').lower() for p in ports if p.get('state') == 'open']

            for device_type, port_patterns in DeviceClassifier.PORT_PATTERNS.items():
                matching_ports = len([p for p in port_patterns if p in open_port_numbers])
                if matching_ports > 0:
                    score = (matching_ports / len(port_patterns)) * 0.5
                    scores[device_type] = scores.get(device_type, 0) + score
                    methods.append('ports')

            # Check service names
            for device_type, service_patterns in DeviceClassifier.SERVICE_PATTERNS.items():
                matching_services = len([s for s in service_names if any(p in s for p in service_patterns)])
                if matching_services > 0:
                    scores[device_type] = scores.get(device_type, 0) + 0.3
                    methods.append('services')

        # Classify based on hostname/NetBIOS name
        name_hints = hostname + ' ' + netbios_name
        if 'printer' in name_hints or 'print' in name_hints:
            scores['printer'] = scores.get('printer', 0) + 0.2
            methods.append('hostname')
        elif 'router' in name_hints or 'gateway' in name_hints:
            scores['router'] = scores.get('router', 0) + 0.2
            methods.append('hostname')
        elif 'nas' in name_hints or 'storage' in name_hints:
            scores['nas'] = scores.get('nas', 0) + 0.2
            methods.append('hostname')
        elif 'camera' in name_hints or 'cam' in name_hints:
            scores['camera'] = scores.get('camera', 0) + 0.2
            methods.append('hostname')

        # Select highest scoring device type
        if scores:
            device_type = max(scores.items(), key=lambda x: x[1])
            classification['device_type'] = device_type[0]
            classification['confidence_score'] = min(device_type[1], 1.0)
            classification['classification_method'] = '+'.join(set(methods))

            # Assign category
            classification['device_category'] = DeviceClassifier._get_category(device_type[0])

            logger.debug("Classified device as '{}' with confidence {:.2f} using {}".format(
                classification['device_type'],
                classification['confidence_score'],
                classification['classification_method']
            ))
        else:
            # No classification possible
            logger.debug("Could not classify device - insufficient data")

        return classification

    @staticmethod
    def _get_category(device_type: str) -> str:
        """Map device type to broader category"""
        categories = {
            'network': ['router', 'switch', 'access_point', 'firewall'],
            'computer': ['workstation', 'server', 'laptop'],
            'mobile': ['mobile', 'tablet', 'smartphone'],
            'iot': ['iot', 'smart_tv', 'camera', 'media_device', 'game_console'],
            'infrastructure': ['printer', 'nas', 'database', 'web_server', 'mail_server', 'file_server'],
        }

        for category, types in categories.items():
            if device_type in types:
                return category

        return 'unknown'
