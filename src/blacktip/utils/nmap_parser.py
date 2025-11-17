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


def _parse_mdns_scripts(host) -> Optional[List[Dict]]:
    """Parse mDNS/Bonjour DNS-SD NSE script output from host element

    Args:
        host: XML host element containing script results

    Returns:
        List of service dictionaries, or None if no services found
    """
    services = []

    # Look for hostscript (host-level scripts)
    hostscript = host.find('hostscript')
    if hostscript is None:
        return None

    # Parse dns-service-discovery script
    dns_sd_script = None
    for script in hostscript.findall('script'):
        if script.get('id') == 'dns-service-discovery':
            dns_sd_script = script
            break

    if dns_sd_script is None:
        return None

    # Parse service tables - each service is in its own table
    for service_table in dns_sd_script.findall('table'):
        service_data = {
            'service_name': None,
            'service_type': None,
            'port': None,
            'target': None,
            'txt_records': []
        }

        # Get service instance name (if available)
        service_name = service_table.get('key')
        if service_name:
            service_data['service_name'] = service_name

        # Parse service details
        for elem in service_table.findall('elem'):
            key = elem.get('key')
            value = elem.text

            if key == 'service':
                service_data['service_type'] = value
            elif key == 'port':
                try:
                    service_data['port'] = int(value)
                except (ValueError, TypeError):
                    pass
            elif key == 'target':
                service_data['target'] = value

        # Parse TXT records table
        for txt_table in service_table.findall('table'):
            if txt_table.get('key') == 'txt':
                for txt_elem in txt_table.findall('elem'):
                    if txt_elem.text:
                        service_data['txt_records'].append(txt_elem.text)

        # Convert TXT records list to string for storage
        if service_data['txt_records']:
            service_data['txt_records'] = '; '.join(service_data['txt_records'])
        else:
            service_data['txt_records'] = None

        # Only add service if we have at least a service type
        if service_data['service_type'] or service_data['service_name']:
            services.append(service_data)

    if not services:
        return None

    logger.debug("Parsed {} mDNS service(s)".format(len(services)))
    return services


def _parse_http_scripts(host) -> Optional[List[Dict]]:
    """Parse HTTP-related NSE script output from host element

    Args:
        host: XML host element containing script results

    Returns:
        List of HTTP data dictionaries (one per port), or None if no data found
    """
    http_data = []

    # Look for port-level scripts
    ports_elem = host.find('ports')
    if ports_elem is None:
        return None

    for port_elem in ports_elem.findall('port'):
        port_num = port_elem.get('portid')
        try:
            port_num = int(port_num)
        except (ValueError, TypeError):
            continue

        port_http_data = {
            'port': port_num,
            'title': None,
            'server': None,
            'status': None,
            'redirect_url': None,
            'robots_txt': None,
            'methods': None,
            'favicon_hash': None
        }

        has_http_data = False

        # Check for HTTP scripts on this port
        for script in port_elem.findall('script'):
            script_id = script.get('id')

            if script_id == 'http-title':
                port_http_data['title'] = script.get('output', '').strip()
                has_http_data = True

            elif script_id == 'http-server-header':
                port_http_data['server'] = script.get('output', '').strip()
                has_http_data = True

            elif script_id == 'http-methods':
                # Extract allowed methods
                methods = []
                for elem in script.findall('elem'):
                    if elem.text:
                        methods.append(elem.text.strip())
                if methods:
                    port_http_data['methods'] = ', '.join(methods)
                    has_http_data = True

            elif script_id == 'http-robots-txt':
                port_http_data['robots_txt'] = script.get('output', '').strip()[:500]  # Limit size
                has_http_data = True

        if has_http_data:
            http_data.append(port_http_data)

    if not http_data:
        return None

    logger.debug("Parsed HTTP data for {} port(s)".format(len(http_data)))
    return http_data


def _parse_ssl_scripts(host) -> Optional[List[Dict]]:
    """Parse SSL/TLS NSE script output from host element

    Args:
        host: XML host element containing script results

    Returns:
        List of SSL data dictionaries (one per port), or None if no data found
    """
    ssl_data = []

    # Look for port-level scripts
    ports_elem = host.find('ports')
    if ports_elem is None:
        return None

    for port_elem in ports_elem.findall('port'):
        port_num = port_elem.get('portid')
        try:
            port_num = int(port_num)
        except (ValueError, TypeError):
            continue

        port_ssl_data = {
            'port': port_num,
            'subject': None,
            'issuer': None,
            'serial': None,
            'not_before': None,
            'not_after': None,
            'sha1_fingerprint': None,
            'sha256_fingerprint': None,
            'ciphers': None,
            'tls_versions': None,
            'vulnerabilities': None
        }

        has_ssl_data = False

        # Check for SSL scripts on this port
        for script in port_elem.findall('script'):
            script_id = script.get('id')

            if script_id == 'ssl-cert':
                # Parse certificate information
                for elem in script.findall('elem'):
                    key = elem.get('key')
                    if key == 'subject':
                        port_ssl_data['subject'] = elem.text
                        has_ssl_data = True
                    elif key == 'issuer':
                        port_ssl_data['issuer'] = elem.text
                        has_ssl_data = True

                # Look for table with certificate details
                for table in script.findall('table'):
                    table_key = table.get('key')
                    if table_key == 'validity':
                        for elem in table.findall('elem'):
                            if elem.get('key') == 'notBefore':
                                port_ssl_data['not_before'] = elem.text
                            elif elem.get('key') == 'notAfter':
                                port_ssl_data['not_after'] = elem.text
                    elif table_key == 'pubkey':
                        for elem in table.findall('elem'):
                            if elem.get('key') == 'bits':
                                # Can store additional info if needed
                                pass

            elif script_id == 'ssl-enum-ciphers':
                # Parse cipher suites and TLS versions
                tls_versions = []
                ciphers = []
                vulns = []

                for table in script.findall('table'):
                    # TLS version tables (e.g., TLSv1.2, TLSv1.3)
                    tls_version = table.get('key')
                    if tls_version and 'TLS' in tls_version.upper():
                        tls_versions.append(tls_version)

                        # Get ciphers for this version
                        for cipher_table in table.findall('table'):
                            if cipher_table.get('key') == 'ciphers':
                                for cipher in cipher_table.findall('table'):
                                    for elem in cipher.findall('elem'):
                                        if elem.get('key') == 'name' and elem.text:
                                            ciphers.append(elem.text)

                    # Check for warnings/vulnerabilities
                    if table.get('key') == 'warnings':
                        for elem in table.findall('elem'):
                            if elem.text:
                                vulns.append(elem.text)

                if tls_versions:
                    port_ssl_data['tls_versions'] = ', '.join(tls_versions)
                    has_ssl_data = True
                if ciphers:
                    # Store up to 10 ciphers to avoid huge strings
                    port_ssl_data['ciphers'] = ', '.join(ciphers[:10])
                    has_ssl_data = True
                if vulns:
                    port_ssl_data['vulnerabilities'] = '; '.join(vulns)
                    has_ssl_data = True

        if has_ssl_data:
            ssl_data.append(port_ssl_data)

    if not ssl_data:
        return None

    logger.debug("Parsed SSL data for {} port(s)".format(len(ssl_data)))
    return ssl_data


def _parse_ssh_scripts(host) -> Optional[List[Dict]]:
    """Parse SSH NSE script output from host element

    Args:
        host: XML host element containing script results

    Returns:
        List of SSH data dictionaries (one per port), or None if no data found
    """
    ssh_data = []

    # Look for port-level scripts
    ports_elem = host.find('ports')
    if ports_elem is None:
        return None

    for port_elem in ports_elem.findall('port'):
        port_num = port_elem.get('portid')
        try:
            port_num = int(port_num)
        except (ValueError, TypeError):
            continue

        port_ssh_data = {
            'port': port_num,
            'protocol_version': None,
            'hostkey_type': None,
            'hostkey_fingerprint': None,
            'hostkey_bits': None,
            'algorithms': None
        }

        has_ssh_data = False

        # Check for SSH scripts on this port
        for script in port_elem.findall('script'):
            script_id = script.get('id')

            if script_id == 'ssh-hostkey':
                # Parse host key information
                hostkeys = []
                for table in script.findall('table'):
                    key_type = None
                    key_fingerprint = None
                    key_bits = None

                    for elem in table.findall('elem'):
                        key = elem.get('key')
                        if key == 'type':
                            key_type = elem.text
                        elif key == 'fingerprint':
                            key_fingerprint = elem.text
                        elif key == 'bits':
                            try:
                                key_bits = int(elem.text)
                            except (ValueError, TypeError):
                                pass

                    if key_type and key_fingerprint:
                        hostkeys.append("{}:{} ({} bits)".format(
                            key_type, key_fingerprint, key_bits if key_bits else 'unknown'))

                        # Use first key for main fields
                        if not port_ssh_data['hostkey_type']:
                            port_ssh_data['hostkey_type'] = key_type
                            port_ssh_data['hostkey_fingerprint'] = key_fingerprint
                            port_ssh_data['hostkey_bits'] = key_bits
                            has_ssh_data = True

            elif script_id == 'ssh2-enum-algos':
                # Parse supported algorithms
                algos = []
                for table in script.findall('table'):
                    algo_type = table.get('key')
                    algo_list = []
                    for elem in table.findall('elem'):
                        if elem.text:
                            algo_list.append(elem.text)
                    if algo_list and algo_type:
                        algos.append("{}: {}".format(algo_type, ', '.join(algo_list[:3])))  # Limit to 3

                if algos:
                    port_ssh_data['algorithms'] = '; '.join(algos)
                    has_ssh_data = True

        if has_ssh_data:
            ssh_data.append(port_ssh_data)

    if not ssh_data:
        return None

    logger.debug("Parsed SSH data for {} port(s)".format(len(ssh_data)))
    return ssh_data


def _parse_vulnerability_scripts(host) -> Optional[List[Dict]]:
    """Parse vulnerability NSE script output from host element

    Args:
        host: XML host element containing script results

    Returns:
        List of vulnerability dictionaries, or None if no vulnerabilities found
    """
    vulns = []

    # Check both port-level and host-level scripts
    script_locations = []

    ports_elem = host.find('ports')
    if ports_elem is not None:
        for port_elem in ports_elem.findall('port'):
            port_num = port_elem.get('portid')
            try:
                port_num = int(port_num)
            except (ValueError, TypeError):
                continue
            script_locations.append(('port', port_num, port_elem))

    hostscript = host.find('hostscript')
    if hostscript is not None:
        script_locations.append(('host', None, hostscript))

    for location_type, port_num, elem in script_locations:
        for script in elem.findall('script'):
            script_id = script.get('id')

            if script_id == 'vulners':
                # Parse vulners script output
                for table in script.findall('table'):
                    vuln_data = {
                        'port': port_num,
                        'vuln_id': None,
                        'title': None,
                        'description': None,
                        'state': 'VULNERABLE',
                        'risk': None,
                        'cvss_score': None,
                        'cve_id': None,
                        'exploit_available': 0
                    }

                    for elem_item in table.findall('elem'):
                        key = elem_item.get('key')
                        value = elem_item.text

                        if key == 'id':
                            vuln_data['vuln_id'] = value
                            # Extract CVE if present
                            if value and value.startswith('CVE-'):
                                vuln_data['cve_id'] = value
                        elif key == 'title':
                            vuln_data['title'] = value
                        elif key == 'cvss':
                            try:
                                vuln_data['cvss_score'] = float(value)
                            except (ValueError, TypeError):
                                pass

                    if vuln_data['vuln_id']:
                        vulns.append(vuln_data)

    if not vulns:
        return None

    logger.debug("Parsed {} vulnerability(ies)".format(len(vulns)))
    return vulns


def _parse_generic_scripts(host) -> Optional[List[Dict]]:
    """Parse any other NSE scripts not handled by specific parsers

    Args:
        host: XML host element containing script results

    Returns:
        List of script output dictionaries, or None if none found
    """
    # Scripts handled by specific parsers (skip these)
    handled_scripts = {
        'nbstat', 'smb-os-discovery', 'smb-protocols', 'smb-security-mode',
        'dns-service-discovery', 'http-title', 'http-server-header',
        'http-methods', 'http-robots-txt', 'ssl-cert',
        'ssl-enum-ciphers', 'ssh-hostkey', 'ssh2-enum-algos', 'vulners'
    }

    generic_scripts = []

    # Check port-level scripts
    ports_elem = host.find('ports')
    if ports_elem is not None:
        for port_elem in ports_elem.findall('port'):
            port_num = port_elem.get('portid')
            try:
                port_num = int(port_num)
            except (ValueError, TypeError):
                continue

            for script in port_elem.findall('script'):
                script_id = script.get('id')
                if script_id not in handled_scripts:
                    output = script.get('output', '')
                    if output:
                        generic_scripts.append({
                            'port': port_num,
                            'script_id': script_id,
                            'output': output[:1000]  # Limit output size
                        })

    # Check host-level scripts
    hostscript = host.find('hostscript')
    if hostscript is not None:
        for script in hostscript.findall('script'):
            script_id = script.get('id')
            if script_id not in handled_scripts:
                output = script.get('output', '')
                if output:
                    generic_scripts.append({
                        'port': None,
                        'script_id': script_id,
                        'output': output[:1000]  # Limit output size
                    })

    if not generic_scripts:
        return None

    logger.debug("Parsed {} generic script output(s)".format(len(generic_scripts)))
    return generic_scripts


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

    # Get mDNS/Bonjour service information from NSE scripts
    mdns_services = _parse_mdns_scripts(host)

    # Get HTTP data from NSE scripts
    http_data = _parse_http_scripts(host)

    # Get SSL/TLS data from NSE scripts
    ssl_data = _parse_ssl_scripts(host)

    # Get SSH data from NSE scripts
    ssh_data = _parse_ssh_scripts(host)

    # Get vulnerability data from NSE scripts
    vuln_data = _parse_vulnerability_scripts(host)

    # Get generic script outputs
    generic_scripts = _parse_generic_scripts(host)

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
        'netbios': netbios_data,
        'mdns_services': mdns_services,
        'http_data': http_data,
        'ssl_data': ssl_data,
        'ssh_data': ssh_data,
        'vuln_data': vuln_data,
        'generic_scripts': generic_scripts
    }

    logger.debug("Parsed nmap scan for {} with {} ports{}{}{}{}{}{}{}".format(
        ip_address, len(ports),
        " and NetBIOS data" if netbios_data else "",
        " and {} mDNS service(s)".format(len(mdns_services)) if mdns_services else "",
        " and {} HTTP port(s)".format(len(http_data)) if http_data else "",
        " and {} SSL port(s)".format(len(ssl_data)) if ssl_data else "",
        " and {} SSH port(s)".format(len(ssh_data)) if ssh_data else "",
        " and {} vulnerability(ies)".format(len(vuln_data)) if vuln_data else "",
        " and {} generic script(s)".format(len(generic_scripts)) if generic_scripts else ""))

    return scan_data
