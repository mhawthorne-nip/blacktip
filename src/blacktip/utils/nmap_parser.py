import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from datetime import datetime

from . import logger


def _parse_netbios_scripts(host) -> Optional[Dict]:
    """Parse NetBIOS/SMB NSE script output from host element

    Args:
        host: XML host element containing script results

    Returns:
        Dictionary containing NetBIOS/SMB data, or None if no data found
    """
    netbios_data = {}

    # Look for hostscript (host-level scripts)
    hostscript = host.find('hostscript')
    if hostscript is None:
        return None

    # Parse nbstat script (NetBIOS name service)
    nbstat_script = None
    for script in hostscript.findall('script'):
        if script.get('id') == 'nbstat':
            nbstat_script = script
            break

    if nbstat_script is not None:
        # Parse NetBIOS names from table
        for table in nbstat_script.findall('table'):
            if table.get('key') == 'names':
                for elem in table.findall('elem'):
                    elem_key = elem.get('key')
                    elem_value = elem.text

                    # Common NetBIOS name types
                    if 'server_name' in elem_key or 'computer_name' in elem_key:
                        netbios_data['netbios_computer_name'] = elem_value
                    elif 'domain_name' in elem_key or 'workgroup' in elem_key:
                        netbios_data['netbios_workgroup'] = elem_value
                    elif 'user' in elem_key:
                        netbios_data['netbios_user'] = elem_value

        # Get MAC address from nbstat if available
        for elem in nbstat_script.findall('elem'):
            if elem.get('key') == 'mac':
                netbios_data['netbios_mac'] = elem.text

    # Parse smb-os-discovery script
    smb_os_script = None
    for script in hostscript.findall('script'):
        if script.get('id') == 'smb-os-discovery':
            smb_os_script = script
            break

    if smb_os_script is not None:
        for elem in smb_os_script.findall('elem'):
            key = elem.get('key')
            value = elem.text

            if key == 'os':
                netbios_data['smb_os'] = value
            elif key == 'computer_name' or key == 'netbios_computer_name':
                netbios_data['smb_computer_name'] = value
            elif key == 'domain_name' or key == 'netbios_domain_name':
                netbios_data['smb_domain_name'] = value
            elif key == 'domain_dns':
                netbios_data['smb_domain_dns'] = value
            elif key == 'forest_dns':
                netbios_data['smb_forest_dns'] = value
            elif key == 'fqdn':
                netbios_data['smb_fqdn'] = value
            elif key == 'system_time':
                netbios_data['smb_system_time'] = value

    # Parse smb-protocols script
    smb_protocols_script = None
    for script in hostscript.findall('script'):
        if script.get('id') == 'smb-protocols':
            smb_protocols_script = script
            break

    if smb_protocols_script is not None:
        # Collect dialects/protocols
        dialects = []
        for table in smb_protocols_script.findall('table'):
            if table.get('key') == 'dialects':
                for elem in table.findall('elem'):
                    if elem.text:
                        dialects.append(elem.text)

        if dialects:
            netbios_data['smb_dialects'] = ', '.join(dialects)

    # Parse smb-security-mode script
    smb_security_script = None
    for script in hostscript.findall('script'):
        if script.get('id') == 'smb-security-mode':
            smb_security_script = script
            break

    if smb_security_script is not None:
        for elem in smb_security_script.findall('elem'):
            key = elem.get('key')
            value = elem.text

            if key == 'message_signing':
                netbios_data['smb_message_signing'] = value
                # Also parse enabled/required from the message_signing value
                if value:
                    if 'enabled' in value.lower():
                        netbios_data['smb_signing_enabled'] = 1
                    if 'required' in value.lower():
                        netbios_data['smb_signing_required'] = 1

    # Return None if no NetBIOS data was found
    if not netbios_data:
        return None

    logger.debug("Parsed NetBIOS data: {}".format(netbios_data))
    return netbios_data


def parse_nmap_xml(xml_content: str) -> Optional[Dict]:
    """Parse nmap XML output and extract relevant information

    Args:
        xml_content: Raw XML string from nmap -oX output

    Returns:
        Dictionary containing parsed scan data, or None if parsing fails
    """
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        logger.error("Failed to parse nmap XML: {}".format(e))
        return None

    # Get nmap run information
    nmap_version = root.get('version', '')
    nmap_args = root.get('args', '')

    # Get scan timing
    scan_start = None
    scan_end = None

    # Start time is in the root element
    start_timestamp = root.get('start')
    if start_timestamp:
        try:
            scan_start = datetime.fromtimestamp(int(start_timestamp)).isoformat()
        except (ValueError, TypeError):
            pass

    # End time is in runstats
    runstats = root.find('runstats')
    if runstats is not None:
        finished = runstats.find('finished')
        if finished is not None:
            end_timestamp = finished.get('time')
            if end_timestamp:
                try:
                    scan_end = datetime.fromtimestamp(int(end_timestamp)).isoformat()
                except (ValueError, TypeError):
                    pass

    # Find the host element
    host = root.find('host')
    if host is None:
        logger.warning("No host element found in nmap XML")
        return None

    # Get host status
    status_elem = host.find('status')
    status = status_elem.get('state', 'unknown') if status_elem is not None else 'unknown'

    # Get IP address
    ip_address = None
    for address in host.findall('address'):
        if address.get('addrtype') == 'ipv4':
            ip_address = address.get('addr')
            break

    if not ip_address:
        logger.warning("No IPv4 address found in nmap XML")
        return None

    # Get MAC address and vendor
    mac_address = None
    mac_vendor = None
    for address in host.findall('address'):
        if address.get('addrtype') == 'mac':
            mac_address = address.get('addr')
            mac_vendor = address.get('vendor')
            break

    # Get hostname
    hostname = None
    hostnames = host.find('hostnames')
    if hostnames is not None:
        hostname_elem = hostnames.find('hostname')
        if hostname_elem is not None:
            hostname = hostname_elem.get('name')

    # Get OS detection
    os_name = None
    os_accuracy = None
    os_elem = host.find('os')
    if os_elem is not None:
        osmatch = os_elem.find('osmatch')
        if osmatch is not None:
            os_name = osmatch.get('name')
            try:
                os_accuracy = int(osmatch.get('accuracy', 0))
            except (ValueError, TypeError):
                pass

    # Get uptime
    uptime_seconds = None
    uptime_elem = host.find('uptime')
    if uptime_elem is not None:
        try:
            uptime_seconds = int(uptime_elem.get('seconds', 0))
        except (ValueError, TypeError):
            pass

    # Get ports
    ports = []
    ports_elem = host.find('ports')
    if ports_elem is not None:
        for port_elem in ports_elem.findall('port'):
            port_num = port_elem.get('portid')
            protocol = port_elem.get('protocol', 'tcp')

            state_elem = port_elem.find('state')
            state = state_elem.get('state', 'unknown') if state_elem is not None else 'unknown'

            service_elem = port_elem.find('service')
            service_name = None
            service_product = None
            service_version = None
            service_extrainfo = None

            if service_elem is not None:
                service_name = service_elem.get('name')
                service_product = service_elem.get('product')
                service_version = service_elem.get('version')
                service_extrainfo = service_elem.get('extrainfo')

            try:
                port_num = int(port_num)
            except (ValueError, TypeError):
                logger.warning("Invalid port number: {}".format(port_num))
                continue

            ports.append({
                'port': port_num,
                'protocol': protocol,
                'state': state,
                'service_name': service_name,
                'service_product': service_product,
                'service_version': service_version,
                'service_extrainfo': service_extrainfo
            })

    # Get NetBIOS/SMB information from NSE scripts
    netbios_data = _parse_netbios_scripts(host)

    scan_data = {
        'ip_address': ip_address,
        'scan_start': scan_start,
        'scan_end': scan_end,
        'nmap_version': nmap_version,
        'nmap_args': nmap_args,
        'status': status,
        'hostname': hostname,
        'mac_address': mac_address,
        'mac_vendor': mac_vendor,
        'os_name': os_name,
        'os_accuracy': os_accuracy,
        'uptime_seconds': uptime_seconds,
        'ports': ports,
        'netbios': netbios_data
    }

    logger.debug("Parsed nmap scan for {} with {} ports{}".format(
        ip_address, len(ports),
        " and NetBIOS data" if netbios_data else ""))

    return scan_data
