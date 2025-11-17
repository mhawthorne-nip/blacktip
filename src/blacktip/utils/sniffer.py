
import logging
from typing import Optional, Dict, List, Any
from mac_vendor_lookup import MacLookup, BaseMacLookup

from .utils import timestamp
from blacktip.exceptions import BlacktipException
from blacktip import __sniff_batch_size__ as SNIFF_BATCH_SIZE
from blacktip import __sniff_batch_timeout__ as SNIFF_BATCH_TIMEOUT

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, ARP

# Use module-specific logger to avoid double logging
logger = logging.getLogger(__name__)


class BlacktipSniffer:
    """ARP packet sniffer with vendor lookup and anomaly detection"""

    def __init__(self):
        """Initialize sniffer with MAC vendor lookup cache"""
        self._vendor_cache: Dict[str, str] = {}
        self._mac_lookup: Optional[BaseMacLookup] = None
        try:
            self._mac_lookup = MacLookup()
            # Update the vendor database on first run
            try:
                self._mac_lookup.update_vendors()
            except Exception as e:
                logger.warning("Could not update MAC vendor database: {}".format(e))
                logger.warning("MAC vendor lookups may fail - check network connectivity and permissions")
            else:
                logger.debug("MAC vendor database updated successfully")
        except Exception as e:
            logger.warning("Failed to initialize MAC vendor lookup: {}".format(e))

    def get_hw_vendor(self, hw_address: str) -> str:
        """Get hardware vendor with caching and error handling

        Args:
            hw_address: MAC address in standard format (XX:XX:XX:XX:XX:XX)

        Returns:
            Vendor name or "Unknown" if not found
        """
        if not hw_address or hw_address == "00:00:00:00:00:00":
            return "Unknown"

        # Check cache first
        if hw_address in self._vendor_cache:
            return self._vendor_cache[hw_address]

        # Try MAC vendor lookup
        vendor = "Unknown"
        if self._mac_lookup:
            try:
                vendor = self._mac_lookup.lookup(hw_address)
                if not vendor:
                    vendor = "Unknown"
            except KeyError:
                # MAC not found in database
                logger.debug("MAC vendor not found for: {}".format(hw_address))
                vendor = "Unknown"
            except Exception as e:
                logger.debug("MAC vendor lookup failed for {}: {}".format(hw_address, e))
                vendor = "Unknown"

        # Cache the result (even if Unknown to avoid repeated lookups)
        self._vendor_cache[hw_address] = vendor
        return vendor
    
    def process_packet(self, packet: Dict[str, Any], db) -> Optional[Dict[str, Any]]:
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
            logger.warning("Invalid packet: hw={} ip={}".format(hw_address, ip_address))
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
            logger.warning("Potential ARP spoofing: {}".format(anomaly_msg))
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
    
    def sniff_arp_packet_batch(self, interface: Optional[str] = None) -> List[Dict[str, Any]]:
        """Sniff a batch of ARP packets from the network

        Args:
            interface: Network interface to sniff on (None for all interfaces)

        Returns:
            List of parsed ARP packet dictionaries
        """
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
            logger.error("Error sniffing packets: {}".format(e))
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
                    logger.debug("Unknown ARP op: {}".format(sniffed_packet[ARP].op))
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
                    logger.debug("Invalid packet: missing src hw/ip")
                    continue

                packets.append(packet)
            except Exception as e:
                logger.warning("Error processing ARP packet: {}".format(e))
                continue

        return packets

    def scrub_address(self, address_type: str, address: str) -> str:
        """Scrub and validate IP or MAC addresses

        Args:
            address_type: Type of address ('ip' or 'hw')
            address: Address string to validate

        Returns:
            Validated address or empty string if invalid

        Raises:
            BlacktipException: If address_type is not supported
        """
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
