
import logging
from ouilookup import OuiLookup

from .utils import timestamp
from blacktip.exceptions import BlacktipException
from blacktip import __sniff_batch_size__ as SNIFF_BATCH_SIZE
from blacktip import __sniff_batch_timeout__ as SNIFF_BATCH_TIMEOUT

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, ARP


class BlacktipSniffer:
    
    def __init__(self):
        """Initialize sniffer with OUI lookup cache"""
        self._oui_cache = {}
        self._oui_lookup = None
        try:
            self._oui_lookup = OuiLookup()
        except Exception as e:
            logging.warning("Failed to initialize OUI lookup: {}".format(e))
    
    def get_hw_vendor(self, hw_address):
        """Get hardware vendor with caching and error handling"""
        if not hw_address or hw_address == "00:00:00:00:00:00":
            return "Unknown"
        
        # Check cache first
        if hw_address in self._oui_cache:
            return self._oui_cache[hw_address]
        
        # Try OUI lookup
        vendor = "Unknown"
        if self._oui_lookup:
            try:
                result = self._oui_lookup.query(hw_address)
                if result and len(result) > 0 and isinstance(result[0], dict):
                    vendor = list(result[0].values())[0] if result[0].values() else "Unknown"
            except Exception as e:
                logging.debug("OUI lookup failed for {}: {}".format(hw_address, e))
        
        # Cache the result (even if Unknown to avoid repeated lookups)
        self._oui_cache[hw_address] = vendor
        return vendor
    
    def process_packet(self, packet, db):
        """Process a packet and update database
        
        Args:
            packet: Parsed ARP packet dictionary
            db: BlacktipDatabase instance
            
        Returns:
            packet_data dictionary or None if invalid
        """
        hw_address = packet["src"]["hw"]
        ip_address = packet["src"]["ip"]
        
        if not hw_address or not ip_address:
            logging.warning("Invalid packet: hw={} ip={}".format(hw_address, ip_address))
            return None

        # Lookup hardware vendor
        hw_vendor = self.get_hw_vendor(hw_address)
        
        # Detect gratuitous ARP
        is_gratuitous = (packet["src"]["ip"] == packet["dst"]["ip"])
        
        # Check for IP/MAC conflicts
        anomalies = []
        previous_mac = db.check_ip_conflict(ip_address, hw_address)
        if previous_mac:
            anomaly_msg = "IP {} previously seen with MAC {}, now with {}".format(
                ip_address, previous_mac, hw_address
            )
            anomalies.append({
                "type": "ip_mac_conflict",
                "message": anomaly_msg,
                "ts": timestamp()
            })
            logging.warning("Potential ARP spoofing: {}".format(anomaly_msg))
            db.log_anomaly("ip_mac_conflict", anomaly_msg, ip_address, hw_address)
        
        # Update database and get new status
        device_id, is_new_ip, is_new_hw = db.upsert_device(
            ip_address, hw_address, hw_vendor, packet["op"], 
            is_new_ip=False, is_new_mac=False
        )
        
        # Optionally log the event (can be disabled for performance)
        # db.log_event(device_id, packet["op"], is_gratuitous)
        
        packet_data = {
            "op": packet["op"],
            "ip": {"addr": ip_address, "new": is_new_ip},
            "hw": {"addr": hw_address, "new": is_new_hw, "vendor": hw_vendor},
            "gratuitous": is_gratuitous,
            "anomalies": anomalies if anomalies else None,
            "ts": packet.get("ts", timestamp())
        }

        return packet_data
    
    def sniff_arp_packet_batch(self, interface=None):

        packets = []
        try:
            kwargs = {
                "filter": "arp",
                "count": SNIFF_BATCH_SIZE,
                "timeout": SNIFF_BATCH_TIMEOUT,
                "store": 1
            }
            if interface:
                kwargs["iface"] = interface
            
            sniffed_packets = sniff(**kwargs)
        except Exception as e:
            logging.error("Error sniffing packets: {}".format(e))
            return packets
        
        for sniffed_packet in sniffed_packets:
            try:
                if not sniffed_packet.haslayer(ARP):
                    continue
                
                packet = {"op": None, "src": {}, "dst": {}, "ts": timestamp()}

                if sniffed_packet[ARP].op == 1:
                    packet["op"] = "request"
                elif sniffed_packet[ARP].op == 2:
                    packet["op"] = "reply"
                else:
                    logging.debug("Unknown ARP op: {}".format(sniffed_packet[ARP].op))
                    continue

                packet["src"] = {
                    "hw": self.scrub_address("hw", sniffed_packet.sprintf("%ARP.hwsrc%")),
                    "ip": self.scrub_address("ip", sniffed_packet.sprintf("%ARP.psrc%")),
                }
                packet["dst"] = {
                    "hw": self.scrub_address("hw", sniffed_packet.sprintf("%ARP.hwdst%")),
                    "ip": self.scrub_address("ip", sniffed_packet.sprintf("%ARP.pdst%")),
                }
                
                # Validate packet data
                if not packet["src"]["hw"] or not packet["src"]["ip"]:
                    logging.debug("Invalid packet: missing src hw/ip")
                    continue
                
                packets.append(packet)
            except Exception as e:
                logging.warning("Error processing ARP packet: {}".format(e))
                continue

        return packets

    def scrub_address(self, address_type, address):
        """Scrub and validate addresses"""
        if not address:
            return ""
        
        if address_type == "ip":
            scrubbed = "".join(x for x in address if x in [".", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"])
            # Basic IP validation
            parts = scrubbed.split(".")
            if len(parts) == 4:
                try:
                    if all(0 <= int(p) <= 255 for p in parts if p):
                        return scrubbed
                except ValueError:
                    pass
            return ""
        elif address_type == "hw":
            scrubbed = "".join(
                x
                for x in address.lower()
                if x in [":", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]
            )
            # Basic MAC validation (should have 5 colons and proper length)
            if scrubbed.count(":") == 5 and len(scrubbed) == 17:
                return scrubbed
            return ""
        else:
            raise BlacktipException("unsupported address_type", address_type)

    def expand_packet_session_data(self, packet, session):

        hw_address_is_new = False
        ip_address_is_new = False
        anomalies = []

        hw_address = packet["src"]["hw"]
        ip_address = packet["src"]["ip"]
        
        if not hw_address or not ip_address:
            logging.warning("Invalid packet: hw={} ip={}".format(hw_address, ip_address))
            return None, session

        # lookup hw_vendor name with caching
        hw_vendor = self.get_hw_vendor(hw_address)
        
        # Detect gratuitous ARP (announcement)
        is_gratuitous = (packet["src"]["ip"] == packet["dst"]["ip"])
        
        # Detect potential ARP spoofing/conflicts
        # Check if this IP was previously seen with a different MAC
        if ip_address in session["ip"]:
            existing_macs = list(session["ip"][ip_address].keys())
            if existing_macs and hw_address not in existing_macs:
                anomalies.append({
                    "type": "ip_mac_conflict",
                    "message": "IP {} previously seen with MAC {}, now with {}".format(
                        ip_address, existing_macs[0], hw_address
                    ),
                    "ts": timestamp()
                })
                logging.warning("Potential ARP spoofing: {}".format(anomalies[-1]["message"]))
        
        # Check if this MAC was previously seen with a different IP
        if hw_address in session["hw"]:
            existing_ips = list(session["hw"][hw_address].keys())
            if existing_ips and ip_address not in existing_ips:
                # This is normal for DHCP, but worth noting
                logging.info("MAC {} changed IP from {} to {}".format(
                    hw_address, existing_ips[-1], ip_address
                ))

        # update session['ip'] data
        if ip_address not in session["ip"].keys():
            ip_address_is_new = True
            session["ip"][ip_address] = {}
        if hw_address not in session["ip"][ip_address].keys():
            session["ip"][ip_address][hw_address] = {
                "count": 0,
                "ts_first": timestamp(),
                "ts_last": None,
                "packets": {"request": 0, "reply": 0}
            }
        session["ip"][ip_address][hw_address]["count"] += 1
        session["ip"][ip_address][hw_address]["ts_last"] = timestamp()
        session["ip"][ip_address][hw_address]["hw_vendor"] = hw_vendor
        session["ip"][ip_address][hw_address]["packets"][packet["op"]] += 1

        # update session['hw'] data
        if hw_address not in session["hw"].keys():
            hw_address_is_new = True
            session["hw"][hw_address] = {}
        if ip_address not in session["hw"][hw_address].keys():
            session["hw"][hw_address][ip_address] = {
                "count": 0,
                "ts_first": timestamp(),
                "ts_last": None,
                "packets": {"request": 0, "reply": 0}
            }
        session["hw"][hw_address][ip_address]["count"] += 1
        session["hw"][hw_address][ip_address]["ts_last"] = timestamp()
        session["hw"][hw_address][ip_address]["hw_vendor"] = hw_vendor
        session["hw"][hw_address][ip_address]["packets"][packet["op"]] += 1
        
        # Add anomalies tracking to session if not present
        if "anomalies" not in session:
            session["anomalies"] = []
        session["anomalies"].extend(anomalies)

        packet_data = {
            "op": packet["op"],
            "ip": {"addr": ip_address, "new": ip_address_is_new},
            "hw": {"addr": hw_address, "new": hw_address_is_new, "vendor": hw_vendor},
            "gratuitous": is_gratuitous,
            "anomalies": anomalies if anomalies else None,
            "ts": packet.get("ts", timestamp())
        }

        return packet_data, session
