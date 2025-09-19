"""
Packet Sniffer Module
Provides functionality to capture and analyze network packets using Scapy
"""

import threading
import time
from datetime import datetime
from typing import List, Dict, Optional, Callable
import json
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='logs/app_20250919.log'
)
logger = logging.getLogger(__name__)

try:
    from scapy.all import sniff, get_if_list, conf, Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    SCAPY_AVAILABLE = True
    logger.info("Scapy successfully imported")
except ImportError as e:
    SCAPY_AVAILABLE = False
    logger.error(f"Failed to import Scapy: {e}")
    raise ImportError("Scapy is required for packet sniffing functionality. Please install it using 'pip install scapy'")


class PacketSniffer:
    def __init__(self, interface: Optional[str] = None, max_packets: int = 5000):
        """
        Initialize the packet sniffer
        
        Args:
            interface: Network interface to sniff on (None for default)
            max_packets: Maximum number of packets to store in memory (default 5000)
        """
        self.interface = interface
        self.max_packets = max_packets
        self.captured_packets = []
        self.is_sniffing = False
        self.sniff_thread = None
        self.packet_count = 0
        self.start_time = None
        
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for packet sniffing functionality")
    
    def start_sniffing(self, filter_string: str = "", packet_count: int = 0, 
                      timeout: int = 0, callback: Optional[Callable] = None) -> bool:
        """
        Start packet capture
        
        Args:
            filter_string: BPF filter string (e.g., "tcp port 80")
            packet_count: Number of packets to capture (0 for unlimited)
            timeout: Timeout in seconds (0 for no timeout)
            callback: Optional callback function for each packet
            
        Returns:
            True if started successfully, False otherwise
        """
        if self.is_sniffing:
            logger.warning("Packet capture already in progress")
            return False
            
        # Verify interface exists if specified
        if self.interface and self.interface not in self.get_available_interfaces():
            logger.error(f"Interface {self.interface} not found")
            return False
            
        try:
            self.is_sniffing = True
            self.start_time = datetime.now()
            self.captured_packets.clear()
            self.packet_count = 0
            
            logger.info(f"Starting packet capture on interface: {self.interface or 'default'}")
            logger.info(f"Filter: {filter_string or 'none'}, Count: {packet_count or 'unlimited'}, Timeout: {timeout or 'none'}")
            
            def packet_handler(packet):
                if not self.is_sniffing:
                    return
                
                try:
                    # Log raw packet summary for debugging
                    logger.debug(f"Received packet: {packet.summary()}")
                    
                    packet_info = self._analyze_packet(packet)
                    if packet_info:
                        logger.debug(f"Analyzed packet: {packet_info}")
                        self.captured_packets.append(packet_info)
                        self.packet_count += 1
                        
                        # Limit memory usage
                        if len(self.captured_packets) > self.max_packets:
                            self.captured_packets.pop(0)
                        
                        if callback:
                            callback(packet_info)
                    else:
                        logger.debug("Packet analysis returned None")
                except Exception as e:
                    logger.error(f"Error in packet handler: {str(e)}")
                    # Continue processing other packets even if one fails
            
            # Start sniffing in a separate thread
            self.sniff_thread = threading.Thread(
                target=self._sniff_worker,
                args=(filter_string, packet_count, timeout, packet_handler),
                daemon=True
            )
            self.sniff_thread.start()
            
            return True
            
        except Exception as e:
            self.is_sniffing = False
            print(f"Error starting packet capture: {e}")
            return False
    
    def stop_sniffing(self):
        """Stop packet capture"""
        self.is_sniffing = False
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=2)
    
    def _sniff_worker(self, filter_string: str, packet_count: int, 
                     timeout: int, packet_handler: Callable):
        """Worker function for packet sniffing"""
        try:
            # Check for root privileges
            if os.geteuid() != 0:
                logger.error("Root privileges required for packet sniffing")
                raise PermissionError("Root privileges required for packet sniffing")
            
            # Set interface in promiscuous mode
            if self.interface:
                try:
                    os.system(f"ip link set {self.interface} promisc on")
                    logger.info(f"Set {self.interface} to promiscuous mode")
                except Exception as e:
                    logger.warning(f"Failed to set promiscuous mode: {e}")
                
            logger.debug("Starting sniff worker thread")
            logger.info(f"Sniffing on interface: {self.interface or 'default'}")
            logger.info(f"Filter string: {filter_string or 'none'}")
            
            # Use monitor=True to capture more packets
            sniff(
                iface=self.interface,
                filter=filter_string,
                prn=packet_handler,
                count=packet_count if packet_count > 0 else 0,
                timeout=timeout if timeout > 0 else None,
                stop_filter=lambda x: not self.is_sniffing,
                store=0,  # Don't store packets in memory
                monitor=True  # Enable monitor mode if possible
            )
            logger.info("Sniffing completed normally")
            
        except Exception as e:
            logger.error(f"Sniffing error: {str(e)}")
            if "permission" in str(e).lower():
                logger.error("Permission denied. Try running with sudo")
            elif "no such device" in str(e).lower():
                logger.error(f"Interface {self.interface} not found or not accessible")
        finally:
            self.is_sniffing = False
            logger.info("Sniffing stopped")
    
    def _analyze_packet(self, packet) -> Optional[Dict]:
        """
        Analyze a captured packet and extract relevant information
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary with packet information or None if not analyzable
        """
        try:
            packet_info = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'length': len(packet),
                'protocol': 'Unknown',
                'src': 'Unknown',
                'dst': 'Unknown',
                'src_port': None,
                'dst_port': None,
                'info': ''
            }
            
            # Ethernet layer
            if packet.haslayer(Ether):
                eth = packet[Ether]
                packet_info['src_mac'] = eth.src
                packet_info['dst_mac'] = eth.dst
            
            # IP layer
            if packet.haslayer(IP):
                ip = packet[IP]
                packet_info['src'] = ip.src
                packet_info['dst'] = ip.dst
                packet_info['ttl'] = ip.ttl
                packet_info['ip_id'] = ip.id
                
                # TCP layer
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    packet_info['protocol'] = 'TCP'
                    packet_info['src_port'] = tcp.sport
                    packet_info['dst_port'] = tcp.dport
                    packet_info['tcp_flags'] = tcp.flags
                    packet_info['seq'] = tcp.seq
                    packet_info['ack'] = tcp.ack
                    
                    # Identify common services
                    if tcp.dport == 80 or tcp.sport == 80:
                        packet_info['service'] = 'HTTP'
                    elif tcp.dport == 443 or tcp.sport == 443:
                        packet_info['service'] = 'HTTPS'
                    elif tcp.dport == 22 or tcp.sport == 22:
                        packet_info['service'] = 'SSH'
                    elif tcp.dport == 21 or tcp.sport == 21:
                        packet_info['service'] = 'FTP'
                    elif tcp.dport == 25 or tcp.sport == 25:
                        packet_info['service'] = 'SMTP'
                
                # UDP layer
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    packet_info['protocol'] = 'UDP'
                    packet_info['src_port'] = udp.sport
                    packet_info['dst_port'] = udp.dport
                    
                    # DNS
                    if packet.haslayer(DNS):
                        dns = packet[DNS]
                        packet_info['service'] = 'DNS'
                        if dns.qr == 0:  # Query
                            if dns.qd:
                                packet_info['dns_query'] = dns.qd.qname.decode('utf-8')
                        else:  # Response
                            packet_info['dns_response'] = True
                
                # ICMP layer
                elif packet.haslayer(ICMP):
                    icmp = packet[ICMP]
                    packet_info['protocol'] = 'ICMP'
                    packet_info['icmp_type'] = icmp.type
                    packet_info['icmp_code'] = icmp.code
            
            # ARP layer
            elif packet.haslayer(ARP):
                arp = packet[ARP]
                packet_info['protocol'] = 'ARP'
                packet_info['arp_op'] = arp.op
                packet_info['src'] = arp.psrc
                packet_info['dst'] = arp.pdst
                packet_info['src_mac'] = arp.hwsrc
                packet_info['dst_mac'] = arp.hwdst
            
            return packet_info
            
        except Exception as e:
            return None
    
    def get_captured_packets(self) -> List[Dict]:
        """
        Get list of captured packets
        
        Returns:
            List of packet information dictionaries
        """
        return self.captured_packets.copy()
    
    def get_statistics(self) -> Dict:
        """
        Get capture statistics
        
        Returns:
            Dictionary with capture statistics
        """
        if not self.start_time:
            return {'error': 'No capture session active'}
        
        duration = (datetime.now() - self.start_time).total_seconds()
        
        # Protocol statistics
        protocol_stats = {}
        service_stats = {}
        
        for packet in self.captured_packets:
            protocol = packet.get('protocol', 'Unknown')
            protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1
            
            service = packet.get('service', 'Unknown')
            if service != 'Unknown':
                service_stats[service] = service_stats.get(service, 0) + 1
        
        return {
            'total_packets': self.packet_count,
            'stored_packets': len(self.captured_packets),
            'duration_seconds': round(duration, 2),
            'packets_per_second': round(self.packet_count / duration, 2) if duration > 0 else 0,
            'protocol_distribution': protocol_stats,
            'service_distribution': service_stats,
            'is_active': self.is_sniffing
        }
    
    def export_packets(self, filename: str, format: str = 'json') -> bool:
        """
        Export captured packets to file
        
        Args:
            filename: Output filename
            format: Export format ('json' or 'csv')
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if format.lower() == 'json':
                with open(filename, 'w') as f:
                    json.dump({
                        'statistics': self.get_statistics(),
                        'packets': self.captured_packets
                    }, f, indent=2)
            
            elif format.lower() == 'csv':
                import csv
                with open(filename, 'w', newline='') as f:
                    if self.captured_packets:
                        writer = csv.DictWriter(f, fieldnames=self.captured_packets[0].keys())
                        writer.writeheader()
                        writer.writerows(self.captured_packets)
            
            return True
            
        except Exception as e:
            print(f"Export error: {e}")
            return False
    
    def get_available_interfaces(self) -> List[str]:
        """
        Get list of available network interfaces
        
        Returns:
            List of interface names
        """
        try:
            return get_if_list()
        except:
            return []
    
    def clear_captured_packets(self):
        """Clear all captured packets from memory"""
        self.captured_packets.clear()
        self.packet_count = 0