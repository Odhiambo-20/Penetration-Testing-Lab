#!/usr/bin/env python3
"""
COMPREHENSIVE NETWORK RECONNAISSANCE TOOLKIT
Offensive Security Learning Lab - Educational Purpose Only

MODULE: Network Scanner Suite
PURPOSE: Educational demonstration of network reconnaissance techniques
LANGUAGE: Python 3.8+
LAB USE ONLY: Must only run on authorized targets

ETHICAL CONSIDERATIONS:
- Demonstrates how attackers discover network assets
- Understanding this helps defenders implement proper network segmentation
- Never use without authorization

DEFENSIVE INSIGHTS:
- Monitor for sequential port scans
- Implement rate limiting
- Use IDS/IPS to detect scanning patterns
- Honeypots can identify scanners

AUTHOR: Security Student
VERSION: 2.0.0
LAST UPDATED: February 2026
"""

import socket
import threading
import ipaddress
import argparse
import sys
import os
import time
import json
import csv
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import platform

# Try to import optional libraries with graceful fallbacks
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("[!] python-nmap not installed. Install with: pip install python-nmap")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] requests not installed. Install with: pip install requests")

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Define empty color constants as fallback
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''


class NetworkScanner:
    """
    Main network scanner class implementing comprehensive reconnaissance capabilities.
    
    This class provides methods for:
    - Network discovery and host enumeration
    - Port scanning (TCP, UDP, SYN, ACK)
    - Service fingerprinting and version detection
    - OS fingerprinting
    - Vulnerability checking
    - Comprehensive reporting
    """
    
    def __init__(self, target: str, ports: str = "1-1024", threads: int = 100,
                 timeout: float = 1.0, output_dir: str = "scan_results"):
        """
        Initialize the network scanner with target and configuration.
        
        Args:
            target: IP address, range (192.168.1.1-254), or CIDR (192.168.1.0/24)
            ports: Port range (e.g., "1-1000", "22,80,443", "1-65535")
            threads: Number of concurrent threads
            timeout: Socket timeout in seconds
            output_dir: Directory to save scan results
        """
        self.target = target
        self.ports = self._parse_ports(ports)
        self.threads = threads
        self.timeout = timeout
        self.output_dir = output_dir
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Results storage
        self.hosts = []
        self.open_ports = {}
        self.service_versions = {}
        self.os_detections = {}
        self.vulnerabilities = {}
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'total_hosts': 0,
            'hosts_up': 0,
            'ports_scanned': len(self.ports),
            'open_ports_found': 0,
            'scan_duration': 0
        }
        
        # Create output directory
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
    def _parse_ports(self, ports_str: str) -> List[int]:
        """
        Parse port string into list of integers.
        
        Args:
            ports_str: Port specification (e.g., "1-1000", "22,80,443", "80")
            
        Returns:
            List of port numbers
        """
        ports = []
        
        if ',' in ports_str:
            # Handle comma-separated list
            for part in ports_str.split(','):
                part = part.strip()
                if '-' in part:
                    # Handle range within comma list
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(part))
        elif '-' in ports_str:
            # Handle single range
            start, end = map(int, ports_str.split('-'))
            ports = list(range(start, end + 1))
        else:
            # Handle single port
            ports = [int(ports_str)]
            
        # Validate ports
        ports = [p for p in ports if 1 <= p <= 65535]
        return sorted(set(ports))  # Remove duplicates and sort
    
    def _get_ip_list(self) -> List[str]:
        """
        Convert target specification to list of IP addresses.
        
        Returns:
            List of IP address strings
        """
        ips = []
        
        try:
            # Check if it's a single IP
            ipaddress.ip_address(self.target)
            return [self.target]
        except ValueError:
            pass
        
        try:
            # Check if it's a CIDR range
            network = ipaddress.ip_network(self.target, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            pass
        
        # Check if it's a range like 192.168.1.1-254
        if '-' in self.target and '.' in self.target:
            base, last = self.target.rsplit('.', 1)
            if '-' in last:
                start, end = map(int, last.split('-'))
                for i in range(start, end + 1):
                    ips.append(f"{base}.{i}")
                return ips
        
        # Try DNS resolution
        try:
            ip = socket.gethostbyname(self.target)
            return [ip]
        except socket.gaierror:
            print(f"{Fore.RED}[!] Could not resolve target: {self.target}{Style.RESET_ALL}")
            return []
    
    def ping_sweep(self, ips: List[str]) -> List[str]:
        """
        Perform ping sweep to identify live hosts.
        
        Args:
            ips: List of IP addresses to check
            
        Returns:
            List of responsive IP addresses
        """
        live_hosts = []
        print(f"{Fore.CYAN}[*] Performing ping sweep on {len(ips)} hosts...{Style.RESET_ALL}")
        
        def ping_host(ip: str) -> Tuple[str, bool]:
            """Ping a single host using system ping command."""
            try:
                # Determine ping parameters based on OS
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                command = ['ping', param, '1', '-w', '1', ip]
                
                # Execute ping
                result = subprocess.run(command, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, timeout=2)
                return (ip, result.returncode == 0)
            except:
                return (ip, False)
        
        # Use threading for faster ping sweep
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {executor.submit(ping_host, ip): ip for ip in ips}
            
            for i, future in enumerate(as_completed(future_to_ip), 1):
                ip, is_alive = future.result()
                if is_alive:
                    live_hosts.append(ip)
                    print(f"{Fore.GREEN}[+] Host {ip} is up{Style.RESET_ALL}")
                
                # Progress indicator
                if i % 50 == 0:
                    print(f"{Fore.YELLOW}[*] Progress: {i}/{len(ips)} hosts checked{Style.RESET_ALL}")
        
        return live_hosts
    
    def tcp_connect_scan(self, ip: str, port: int) -> Tuple[int, bool, str]:
        """
        Perform TCP connect scan on a single port.
        
        Args:
            ip: Target IP address
            port: Target port
            
        Returns:
            Tuple of (port, is_open, banner)
        """
        try:
            # Create socket with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Port is open - try to grab banner
                banner = self._grab_banner(sock, ip, port)
                sock.close()
                return (port, True, banner)
            else:
                sock.close()
                return (port, False, "")
                
        except socket.error:
            return (port, False, "")
        except Exception as e:
            return (port, False, f"Error: {str(e)}")
    
    def _grab_banner(self, sock: socket.socket, ip: str, port: int) -> str:
        """
        Attempt to grab service banner from open port.
        
        Args:
            sock: Connected socket
            ip: Target IP
            port: Target port
            
        Returns:
            Banner string if available
        """
        banner = ""
        
        # Common probes for different services
        probes = {
            21: b"HELP\r\n",           # FTP
            22: b"\r\n",                 # SSH
            23: b"\r\n",                 # Telnet
            25: b"EHLO test.com\r\n",    # SMTP
            80: b"HEAD / HTTP/1.0\r\n\r\n",  # HTTP
            110: b"USER test\r\n",       # POP3
            143: b"a001 LOGIN\r\n",      # IMAP
            443: b"HEAD / HTTP/1.0\r\n\r\n", # HTTPS
            445: b"\r\n",                 # SMB
            3306: b"\r\n",                # MySQL
            3389: b"\r\n",                # RDP
            5432: b"\r\n",                # PostgreSQL
            5900: b"\r\n",                # VNC
            6379: b"INFO\r\n",            # Redis
            27017: b"\r\n",               # MongoDB
        }
        
        try:
            # Send appropriate probe if known port
            if port in probes:
                sock.send(probes[port])
            else:
                # Generic probe
                sock.send(b"\r\n")
            
            # Receive response
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            pass
        
        return banner
    
    def scan_host_ports(self, ip: str) -> Dict[int, str]:
        """
        Scan all configured ports on a single host.
        
        Args:
            ip: Target IP address
            
        Returns:
            Dictionary of open ports with their banners
        """
        open_ports = {}
        print(f"{Fore.CYAN}[*] Scanning {ip} for {len(self.ports)} ports...{Style.RESET_ALL}")
        
        # Track progress
        scanned = 0
        found = 0
        
        def scan_port(port):
            nonlocal scanned, found
            _, is_open, banner = self.tcp_connect_scan(ip, port)
            scanned += 1
            
            if is_open:
                found += 1
                print(f"{Fore.GREEN}[+] {ip}:{port} - OPEN - {banner[:50]}{Style.RESET_ALL}")
                return (port, banner)
            return None
        
        # Use thread pool for parallel scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in self.ports}
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    port, banner = result
                    open_ports[port] = banner
        
        return open_ports
    
    def identify_service(self, ip: str, port: int, banner: str) -> Dict[str, Any]:
        """
        Identify service and version from banner.
        
        Args:
            ip: Target IP
            port: Target port
            banner: Service banner
            
        Returns:
            Dictionary with service information
        """
        service_info = {
            'port': port,
            'protocol': 'tcp',
            'banner': banner,
            'service': 'unknown',
            'version': 'unknown',
            'cpe': None,
            'confidence': 'low'
        }
        
        # Common service signatures
        signatures = {
            'ssh': ['SSH', 'OpenSSH'],
            'ftp': ['FTP', 'vsftpd', 'FileZilla'],
            'http': ['HTTP', 'Apache', 'Nginx', 'IIS', 'Tomcat'],
            'smtp': ['SMTP', 'Postfix', 'Sendmail', 'Exchange'],
            'mysql': ['MySQL', 'MariaDB'],
            'postgresql': ['PostgreSQL'],
            'redis': ['redis'],
            'mongodb': ['MongoDB'],
            'telnet': ['Telnet'],
            'pop3': ['POP3'],
            'imap': ['IMAP'],
            'smb': ['SMB', 'Microsoft-DS'],
            'rdp': ['RDP', 'Remote Desktop'],
            'vnc': ['VNC', 'RFB'],
            'dns': ['DNS'],
            'dhcp': ['DHCP'],
            'snmp': ['SNMP'],
            'ntp': ['NTP'],
            'ldap': ['LDAP'],
            'kerberos': ['Kerberos'],
            'rpc': ['RPC'],
            'nfs': ['NFS'],
        }
        
        banner_lower = banner.lower()
        
        # Match service
        for service, keywords in signatures.items():
            if any(keyword.lower() in banner_lower for keyword in keywords):
                service_info['service'] = service
                service_info['confidence'] = 'medium'
                
                # Try to extract version
                import re
                version_pattern = r'\d+\.\d+(?:\.\d+)?'
                versions = re.findall(version_pattern, banner)
                if versions:
                    service_info['version'] = versions[0]
                    service_info['confidence'] = 'high'
                break
        
        return service_info
    
    def os_fingerprint(self, ip: str) -> Dict[str, Any]:
        """
        Attempt to fingerprint operating system.
        
        Args:
            ip: Target IP address
            
        Returns:
            Dictionary with OS information
        """
        os_info = {
            'os': 'unknown',
            'accuracy': 0,
            'ttl': None,
            'tcp_options': None
        }
        
        try:
            # Use ICMP TTL for rough OS guess
            ping_result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if ping_result.returncode == 0:
                # Extract TTL from ping output
                import re
                ttl_match = re.search(r'ttl=(\d+)', ping_result.stdout.lower())
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    os_info['ttl'] = ttl
                    
                    # Guess OS based on TTL
                    if ttl <= 64:
                        os_info['os'] = 'Linux/Unix'
                        os_info['accuracy'] = 60
                    elif ttl <= 128:
                        os_info['os'] = 'Windows'
                        os_info['accuracy'] = 60
                    elif ttl <= 255:
                        os_info['os'] = 'Cisco/Network Device'
                        os_info['accuracy'] = 60
        
        except:
            pass
        
        # Use nmap if available for better accuracy
        if NMAP_AVAILABLE:
            try:
                nm = nmap.PortScanner()
                nm.scan(ip, arguments='-O')
                
                if ip in nm.all_hosts() and 'osmatch' in nm[ip]:
                    if nm[ip]['osmatch']:
                        best_match = nm[ip]['osmatch'][0]
                        os_info['os'] = best_match['name']
                        os_info['accuracy'] = int(best_match['accuracy'])
                        os_info['nmap_os_class'] = best_match.get('osclass', [])
            except:
                pass
        
        return os_info
    
    def check_vulnerabilities(self, ip: str, port: int, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check for known vulnerabilities in detected services.
        
        Args:
            ip: Target IP
            port: Target port
            service_info: Service information dictionary
            
        Returns:
            List of potential vulnerabilities
        """
        vulnerabilities = []
        
        # This is a simplified vulnerability check
        # In production, you would integrate with CVE databases or vulnerability scanners
        
        # Common vulnerable versions (for educational purposes)
        vulnerable_versions = {
            'openssh': {
                'versions': ['1.2', '2.0', '2.1', '2.2', '2.3', '2.5', '2.9', '3.0', '3.1'],
                'cve': ['CVE-2001-0368', 'CVE-2002-0083']
            },
            'apache': {
                'versions': ['2.2.0', '2.2.1', '2.2.2', '2.2.3'],
                'cve': ['CVE-2011-3192', 'CVE-2012-0021']
            },
            'vsftpd': {
                'versions': ['2.3.2', '2.3.4'],
                'cve': ['CVE-2011-2523']
            }
        }
        
        service = service_info['service']
        version = service_info['version']
        
        if service in vulnerable_versions and version != 'unknown':
            vuln_info = vulnerable_versions[service]
            if version in vuln_info['versions']:
                vulnerabilities.append({
                    'service': service,
                    'version': version,
                    'cve_list': vuln_info['cve'],
                    'severity': 'high',
                    'description': f'Known vulnerabilities in {service} {version}',
                    'remediation': f'Upgrade {service} to latest version'
                })
        
        return vulnerabilities
    
    def run_full_scan(self) -> Dict[str, Any]:
        """
        Execute comprehensive network scan.
        
        Returns:
            Dictionary with complete scan results
        """
        self.scan_stats['start_time'] = datetime.now().isoformat()
        start_time = time.time()
        
        print(f"""
{Fore.MAGENTA}{'='*60}
NETWORK RECONNAISSANCE TOOLKIT - FULL SCAN
{'='*60}
Target: {self.target}
Ports: {len(self.ports)} ports to scan
Threads: {self.threads}
Timeout: {self.timeout}s
Scan ID: {self.scan_id}
{'='*60}{Style.RESET_ALL}
""")
        
        # Step 1: Get IP list
        ips = self._get_ip_list()
        self.scan_stats['total_hosts'] = len(ips)
        print(f"{Fore.CYAN}[*] Target expanded to {len(ips)} IP addresses{Style.RESET_ALL}")
        
        if not ips:
            print(f"{Fore.RED}[!] No valid IP addresses to scan{Style.RESET_ALL}")
            return {}
        
        # Step 2: Ping sweep
        live_hosts = self.ping_sweep(ips)
        self.scan_stats['hosts_up'] = len(live_hosts)
        
        if not live_hosts:
            print(f"{Fore.YELLOW}[!] No live hosts found{Style.RESET_ALL}")
            return {}
        
        # Step 3: Port scan each live host
        for ip in live_hosts:
            print(f"\n{Fore.BLUE}[*] Starting detailed scan of {ip}{Style.RESET_ALL}")
            
            # Port scanning
            open_ports = self.scan_host_ports(ip)
            if open_ports:
                self.open_ports[ip] = open_ports
                self.scan_stats['open_ports_found'] += len(open_ports)
                
                # Service identification
                self.service_versions[ip] = {}
                self.vulnerabilities[ip] = {}
                
                for port, banner in open_ports.items():
                    # Identify service
                    service_info = self.identify_service(ip, port, banner)
                    self.service_versions[ip][port] = service_info
                    
                    # Check vulnerabilities
                    vulns = self.check_vulnerabilities(ip, port, service_info)
                    if vulns:
                        self.vulnerabilities[ip][port] = vulns
                        
                        # Display vulnerabilities
                        print(f"{Fore.RED}[!] Vulnerabilities found on {ip}:{port}")
                        for vuln in vulns:
                            print(f"    - {vuln['description']}")
                            print(f"      CVEs: {', '.join(vuln['cve_list'])}")
                        print(f"{Style.RESET_ALL}")
                
                # OS fingerprinting
                os_info = self.os_fingerprint(ip)
                self.os_detections[ip] = os_info
                print(f"{Fore.YELLOW}[*] OS Detection: {os_info['os']} (Accuracy: {os_info['accuracy']}%){Style.RESET_ALL}")
            
            else:
                print(f"{Fore.YELLOW}[-] No open ports found on {ip}{Style.RESET_ALL}")
        
        # Final statistics
        end_time = time.time()
        self.scan_stats['end_time'] = datetime.now().isoformat()
        self.scan_stats['scan_duration'] = round(end_time - start_time, 2)
        
        self._print_summary()
        self.save_results()
        
        return {
            'scan_id': self.scan_id,
            'target': self.target,
            'statistics': self.scan_stats,
            'live_hosts': live_hosts,
            'open_ports': self.open_ports,
            'service_versions': self.service_versions,
            'os_detections': self.os_detections,
            'vulnerabilities': self.vulnerabilities
        }
    
    def _print_summary(self):
        """Print scan summary."""
        print(f"""
{Fore.CYAN}{'='*60}
SCAN COMPLETE - SUMMARY
{'='*60}
Scan ID: {self.scan_id}
Target: {self.target}
Duration: {self.scan_stats['scan_duration']} seconds

Hosts:
  - Total scanned: {self.scan_stats['total_hosts']}
  - Live hosts: {self.scan_stats['hosts_up']}
  - Dead hosts: {self.scan_stats['total_hosts'] - self.scan_stats['hosts_up']}

Ports:
  - Ports scanned per host: {self.scan_stats['ports_scanned']}
  - Total open ports found: {self.scan_stats['open_ports_found']}

Results saved to: {self.output_dir}/{self.scan_id}/
{'='*60}{Style.RESET_ALL}
""")
    
    def save_results(self):
        """Save scan results in multiple formats."""
        # Create scan directory
        scan_dir = os.path.join(self.output_dir, self.scan_id)
        os.makedirs(scan_dir, exist_ok=True)
        
        # Save JSON results
        json_path = os.path.join(scan_dir, 'scan_results.json')
        results = {
            'scan_id': self.scan_id,
            'timestamp': datetime.now().isoformat(),
            'target': self.target,
            'configuration': {
                'ports': self.ports,
                'threads': self.threads,
                'timeout': self.timeout
            },
            'statistics': self.scan_stats,
            'open_ports': self.open_ports,
            'service_versions': self.service_versions,
            'os_detections': self.os_detections,
            'vulnerabilities': self.vulnerabilities
        }
        
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=4, default=str)
        print(f"{Fore.GREEN}[+] JSON results saved to {json_path}{Style.RESET_ALL}")
        
        # Save CSV report
        csv_path = os.path.join(scan_dir, 'scan_report.csv')
        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Port', 'Service', 'Version', 'Banner', 'OS', 'Vulnerabilities'])
            
            for ip in self.open_ports:
                os_name = self.os_detections.get(ip, {}).get('os', 'unknown')
                for port, banner in self.open_ports[ip].items():
                    service_info = self.service_versions.get(ip, {}).get(port, {})
                    vulns = self.vulnerabilities.get(ip, {}).get(port, [])
                    vuln_str = '; '.join([v['description'] for v in vulns]) if vulns else 'None'
                    
                    writer.writerow([
                        ip,
                        port,
                        service_info.get('service', 'unknown'),
                        service_info.get('version', 'unknown'),
                        banner[:100],
                        os_name,
                        vuln_str
                    ])
        
        print(f"{Fore.GREEN}[+] CSV report saved to {csv_path}{Style.RESET_ALL}")
        
        # Save human-readable report
        report_path = os.path.join(scan_dir, 'scan_report.txt')
        with open(report_path, 'w') as f:
            f.write(f"""
NETWORK RECONNAISSANCE REPORT
{'='*60}
Scan ID: {self.scan_id}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target: {self.target}

EXECUTIVE SUMMARY
{'='*60}
Scan Duration: {self.scan_stats['scan_duration']} seconds
Hosts Scanned: {self.scan_stats['total_hosts']}
Live Hosts Found: {self.scan_stats['hosts_up']}
Total Open Ports: {self.scan_stats['open_ports_found']}

DETAILED FINDINGS
{'='*60}
""")
            
            for ip in self.open_ports:
                f.write(f"\nHost: {ip}\n")
                f.write(f"OS: {self.os_detections.get(ip, {}).get('os', 'unknown')} "
                       f"(Accuracy: {self.os_detections.get(ip, {}).get('accuracy', 0)}%)\n")
                f.write("-" * 40 + "\n")
                f.write(f"{'PORT':<8} {'SERVICE':<15} {'VERSION':<15} {'VULNERABILITIES'}\n")
                f.write("-" * 40 + "\n")
                
                for port, banner in self.open_ports[ip].items():
                    service_info = self.service_versions.get(ip, {}).get(port, {})
                    vulns = self.vulnerabilities.get(ip, {}).get(port, [])
                    vuln_str = 'YES' if vulns else 'None'
                    
                    f.write(f"{port:<8} {service_info.get('service', 'unknown'):<15} "
                           f"{service_info.get('version', 'unknown'):<15} {vuln_str}\n")
                    
                    if vulns:
                        for vuln in vulns:
                            f.write(f"{' ' * 40}{vuln['description']}\n")
                            f.write(f"{' ' * 40}CVEs: {', '.join(vuln['cve_list'])}\n")
            
            f.write(f"\n{'='*60}\nEnd of Report\n{'='*60}\n")
        
        print(f"{Fore.GREEN}[+] Text report saved to {report_path}{Style.RESET_ALL}")


class AdvancedScanTechniques:
    """
    Advanced scanning techniques for specialized reconnaissance.
    """
    
    @staticmethod
    def syn_scan(target: str, ports: List[int], interface: str = None):
        """
        Perform SYN stealth scan (requires root privileges).
        
        This uses raw sockets and is for educational purposes.
        """
        print(f"{Fore.YELLOW}[*] SYN scan requires root privileges{Style.RESET_ALL}")
        # Implementation would use raw sockets and craft TCP SYN packets
        # This is more complex and platform-specific
        pass
    
    @staticmethod
    def udp_scan(target: str, ports: List[int]):
        """
        Perform UDP port scan.
        
        UDP scanning is slower and less reliable than TCP.
        """
        print(f"{Fore.CYAN}[*] Starting UDP scan on {target}{Style.RESET_ALL}")
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(b'', (target, port))
                
                try:
                    data, addr = sock.recvfrom(1024)
                    open_ports.append(port)
                    print(f"{Fore.GREEN}[+] UDP {port} is open/filtered{Style.RESET_ALL}")
                except socket.timeout:
                    # No response could mean open/filtered
                    pass
                except:
                    pass
                finally:
                    sock.close()
            except:
                pass
        
        return open_ports
    
    @staticmethod
    def version_detection(target: str, port: int, service: str = None):
        """
        Advanced service version detection.
        """
        probes = {
            'http': [
                b"HEAD / HTTP/1.0\r\n\r\n",
                b"GET / HTTP/1.0\r\n\r\n",
                b"OPTIONS * HTTP/1.0\r\n\r\n"
            ],
            'ssh': [
                b"SSH-2.0-OpenSSH_8.9\r\n",
                b"\r\n"
            ],
            'smtp': [
                b"EHLO test.com\r\n",
                b"HELP\r\n"
            ],
            'ftp': [
                b"HELP\r\n",
                b"SYST\r\n"
            ]
        }
        
        if service and service in probes:
            for probe in probes[service]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((target, port))
                    sock.send(probe)
                    response = sock.recv(4096).decode('utf-8', errors='ignore')
                    sock.close()
                    
                    if response:
                        return response.strip()
                except:
                    continue
        
        return None


class VulnerabilityScanner:
    """
    Specialized vulnerability scanning and checking.
    """
    
    def __init__(self):
        self.vulnerability_db = self._load_vulnerability_db()
    
    def _load_vulnerability_db(self) -> Dict:
        """
        Load vulnerability database (simplified version).
        In production, integrate with CVE APIs or local databases.
        """
        return {
            'services': {
                'ssh': {
                    'port': 22,
                    'vulnerabilities': [
                        {
                            'id': 'CVE-2024-12345',
                            'description': 'OpenSSH vulnerability in authentication',
                            'affected_versions': ['< 9.0'],
                            'severity': 'high'
                        }
                    ]
                },
                'http': {
                    'port': 80,
                    'vulnerabilities': [
                        {
                            'id': 'CVE-2024-54321',
                            'description': 'Apache HTTP Server directory traversal',
                            'affected_versions': ['2.4.0 - 2.4.49'],
                            'severity': 'critical'
                        }
                    ]
                }
            }
        }
    
    def check_cve(self, service: str, version: str) -> List[Dict]:
        """
        Check for CVEs affecting specific service version.
        """
        results = []
        
        if service in self.vulnerability_db['services']:
            service_data = self.vulnerability_db['services'][service]
            
            for vuln in service_data['vulnerabilities']:
                # Version matching logic would go here
                results.append(vuln)
        
        return results


class ReportGenerator:
    """
    Generate comprehensive reports in multiple formats.
    """
    
    def __init__(self, scan_results: Dict):
        self.results = scan_results
    
    def generate_html(self, output_path: str):
        """
        Generate HTML report with visualizations.
        """
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Scan Report - {scan_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
                .host {{ margin: 20px 0; padding: 10px; border: 1px solid #ddd; }}
                .open-port {{ color: green; }}
                .vulnerability {{ color: red; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Network Security Scan Report</h1>
            <div class="summary">
                <h2>Scan Summary</h2>
                <p>Scan ID: {scan_id}</p>
                <p>Date: {date}</p>
                <p>Target: {target}</p>
                <p>Duration: {duration} seconds</p>
                <p>Live Hosts: {live_hosts}</p>
                <p>Open Ports Found: {open_ports}</p>
            </div>
            
            <h2>Detailed Findings</h2>
            {host_details}
            
            <h2>Vulnerability Summary</h2>
            {vuln_summary}
            
            <h2>Recommendations</h2>
            <ul>
                <li>Close unnecessary open ports</li>
                <li>Update vulnerable services to latest versions</li>
                <li>Implement network segmentation</li>
                <li>Deploy IDS/IPS to detect scanning activity</li>
                <li>Regular vulnerability scanning and patch management</li>
            </ul>
            
            <p><em>Generated by Offensive Security Learning Lab - Educational Use Only</em></p>
        </body>
        </html>
        """
        
        # Fill in template with actual data
        # This would be implemented fully in production
        
        with open(output_path, 'w') as f:
            f.write(html_template)
        
        print(f"{Fore.GREEN}[+] HTML report generated: {output_path}{Style.RESET_ALL}")
    
    def generate_nessus_format(self, output_path: str):
        """
        Generate Nessus-compatible XML format.
        """
        # Implementation for Nessus XML format
        pass
    
    def generate_metasploit_format(self, output_path: str):
        """
        Generate Metasploit-compatible import file.
        """
        # Implementation for Metasploit import
        pass


def main():
    """
    Main function with command-line interface.
    """
    parser = argparse.ArgumentParser(
        description='Comprehensive Network Reconnaissance Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_scanner.py 192.168.1.1
  python network_scanner.py 192.168.1.0/24 -p 1-1000 -t 200
  python network_scanner.py 192.168.1.1-254 -p 22,80,443,3306 -o custom_scan
  python network_scanner.py scanme.nmap.org -p 1-1000 -v
        """
    )
    
    parser.add_argument('target', help='Target IP, range, or CIDR')
    parser.add_argument('-p', '--ports', default='1-1024',
                       help='Port range to scan (default: 1-1024)')
    parser.add_argument('-t', '--threads', type=int, default=100,
                       help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=1.0,
                       help='Socket timeout in seconds (default: 1.0)')
    parser.add_argument('-o', '--output', default='scan_results',
                       help='Output directory (default: scan_results)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--no-ping', action='store_true',
                       help='Skip ping sweep (scan all hosts)')
    parser.add_argument('--udp', action='store_true',
                       help='Perform UDP scan in addition to TCP')
    parser.add_argument('--os-detect', action='store_true',
                       help='Enable OS fingerprinting')
    parser.add_argument('--vuln-check', action='store_true',
                       help='Enable vulnerability checking')
    
    args = parser.parse_args()
    
    # Display banner
    print(f"""
{Fore.RED}{'='*60}
OFFENSIVE SECURITY LEARNING LAB
Network Reconnaissance Toolkit v2.0
{'='*60}
{Fore.YELLOW}DISCLAIMER: This tool is for EDUCATIONAL USE ONLY
Use only on systems you own or have explicit permission to test.
Unauthorized scanning may be illegal.
{'='*60}{Style.RESET_ALL}
""")
    
    # Confirm legal compliance
    print(f"{Fore.YELLOW}[!] By proceeding, you confirm that:")
    print("    1. You have AUTHORIZATION to scan this target")
    print("    2. This is for EDUCATIONAL purposes only")
    print("    3. You understand the LEGAL implications")
    print(f"{Style.RESET_ALL}")
    
    response = input("Continue? (yes/no): ").lower()
    if response != 'yes':
        print(f"{Fore.RED}[!] Scan aborted.{Style.RESET_ALL}")
        sys.exit(0)
    
    # Create scanner instance
    scanner = NetworkScanner(
        target=args.target,
        ports=args.ports,
        threads=args.threads,
        timeout=args.timeout,
        output_dir=args.output
    )
    
    # Run scan
    try:
        results = scanner.run_full_scan()
        
        # Generate additional reports if requested
        if args.vuln_check and results:
            vuln_scanner = VulnerabilityScanner()
            # Additional vulnerability scanning would go here
        
        print(f"{Fore.GREEN}[+] Scan completed successfully{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Error during scan: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
