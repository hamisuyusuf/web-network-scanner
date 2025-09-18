"""
Port Scanner Module
Provides functionality to scan ports on target hosts using multithreading
"""

import socket
import threading
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional


class PortScanner:
    def __init__(self, timeout: float = 1.0, max_threads: int = 100):
        """
        Initialize the port scanner
        
        Args:
            timeout: Socket timeout in seconds
            max_threads: Maximum number of threads to use
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.scan_results = {}
        
    def scan_port(self, host: str, port: int) -> Tuple[str, int, bool, str]:
        """
        Scan a single port on a host
        
        Args:
            host: Target host IP or hostname
            port: Port number to scan
            
        Returns:
            Tuple of (host, port, is_open, service_info)
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    # Try to get service name
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "Unknown"
                    return (host, port, True, service)
                else:
                    return (host, port, False, "Closed")
                    
        except socket.gaierror:
            return (host, port, False, "Host not found")
        except Exception as e:
            return (host, port, False, f"Error: {str(e)}")
    
    def scan_host_ports(self, host: str, ports: List[int]) -> Dict:
        """
        Scan multiple ports on a single host
        
        Args:
            host: Target host
            ports: List of ports to scan
            
        Returns:
            Dictionary with scan results
        """
        open_ports = []
        closed_ports = []
        scan_start = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, host, port): port 
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                host_result, port, is_open, service = future.result()
                
                if is_open:
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'state': 'open'
                    })
                else:
                    closed_ports.append({
                        'port': port,
                        'service': service,
                        'state': 'closed'
                    })
        
        scan_end = time.time()
        scan_duration = round(scan_end - scan_start, 2)
        
        return {
            'host': host,
            'scan_time': scan_duration,
            'total_ports': len(ports),
            'open_ports': open_ports,
            'closed_ports': closed_ports,
            'open_count': len(open_ports),
            'closed_count': len(closed_ports)
        }
    
    def scan_network_range(self, network: str, ports: List[int]) -> List[Dict]:
        """
        Scan multiple hosts in a network range
        
        Args:
            network: Network in CIDR notation (e.g., '192.168.1.0/24')
            ports: List of ports to scan
            
        Returns:
            List of scan results for each host
        """
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            hosts = list(network_obj.hosts())
            
            results = []
            for host in hosts:
                host_str = str(host)
                # First check if host is alive (ping port 80 or 22)
                if self.is_host_alive(host_str):
                    result = self.scan_host_ports(host_str, ports)
                    if result['open_count'] > 0:  # Only include hosts with open ports
                        results.append(result)
            
            return results
            
        except ValueError as e:
            return [{'error': f"Invalid network format: {str(e)}"}]
    
    def is_host_alive(self, host: str) -> bool:
        """
        Check if a host is alive by attempting to connect to common ports
        
        Args:
            host: Target host
            
        Returns:
            True if host responds, False otherwise
        """
        common_ports = [80, 443, 22, 21, 25, 53, 110, 995, 993, 143, 5000]
        
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)  # Very short timeout for host detection
                    if sock.connect_ex((host, port)) == 0:
                        return True
            except:
                continue
        return False
    
    def get_common_ports(self) -> List[int]:
        """
        Get list of commonly scanned ports
        
        Returns:
            List of common port numbers
        """
        return [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 993, 995, 1723, 3306, 3389, 5432, 5000, 8080, 5000
        ]
    
    def get_port_range(self, start: int, end: int) -> List[int]:
        """
        Generate a range of ports
        
        Args:
            start: Starting port number
            end: Ending port number
            
        Returns:
            List of port numbers in the range
        """
        return list(range(start, end + 1))
