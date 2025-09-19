"""
Port Scanner Module
Provides functionality to scan ports on target hosts using multithreading
"""

import socket
import threading
import time
import ipaddress
import os
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
        # Common service names for quick lookup
        common_services = {
            5000: 'Flask/Web Server'  # Main service running
        }
        
        try:
            # Try both IPv4 and IPv6
            for socket_family in [socket.AF_INET, socket.AF_INET6]:
                try:
                    sock = socket.socket(socket_family, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    
                    # Adjust address based on socket family
                    if socket_family == socket.AF_INET:
                        address = host
                    else:
                        # Skip IPv6 if not a localhost scan
                        if host not in ['127.0.0.1', 'localhost', '::1']:
                            continue
                        address = '::1'
                    
                    result = sock.connect_ex((address, port))
                    
                    if result == 0:
                        # Get service name
                        service = common_services.get(port, "Unknown")
                        if service == "Unknown":
                            try:
                                service = socket.getservbyport(port)
                            except OSError:
                                pass
                        
                        # Try to get additional service info for HTTP
                        try:
                            if port in [80, 8080, 5000]:
                                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                                response = sock.recv(1024).decode('utf-8', 'ignore')
                                if "Server:" in response:
                                    service = f"{service} ({response.split('Server:')[1].split('\\r')[0].strip()})"
                        except:
                            pass
                        
                        sock.close()
                        return (host, port, True, service)
                    sock.close()
                except socket.error:
                    continue
                    
            return (host, port, False, "Closed")
                
        except socket.gaierror:
            return (host, port, False, "Host not found")
        except ConnectionRefusedError:
            return (host, port, False, "Connection refused")
        except TimeoutError:
            return (host, port, False, "Timeout")
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
        # For localhost, just check if we can connect to port 5000
        if host in ['127.0.0.1', 'localhost', '::1']:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1.0)
                    if sock.connect_ex((host, 5000)) == 0:
                        return True
            except:
                pass
            return True  # Consider localhost always alive
            
        # For remote hosts
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)
                return sock.connect_ex((host, 5000)) == 0
        except:
            return False
    
    def get_common_ports(self) -> List[int]:
        """
        Get list of commonly scanned ports
        
        Returns:
            List of common port numbers
        """
        return [
            5000,  # Flask web server
            80,    # HTTP
            443,   # HTTPS
            8080,  # Alternative HTTP
            3000,  # Development servers
            4000,  # Development servers
            8000   # Development servers
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
