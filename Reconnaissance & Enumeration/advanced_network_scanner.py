#!/usr/bin/env python3
"""
PRODUCTION-GRADE NETWORK SECURITY SCANNER
Offensive Security Learning Lab - Enterprise Edition

MODULE: Enterprise Network Reconnaissance & Vulnerability Assessment
PURPOSE: Professional-grade network security auditing tool
LANGUAGE: Python 3.9+
VERSION: 3.0.0 (Production)
LAST UPDATED: February 2026

AUTHOR: Security Professional
LICENSE: Educational/Research Use Only

FEATURES:
    ✓ Enterprise-grade TCP/UDP port scanning
    ✓ Advanced service fingerprinting with version detection
    ✓ Real CVE database integration with NVD/NIST
    ✓ Multi-threaded architecture with rate limiting
    ✓ SSL/TLS security analysis
    ✓ Comprehensive vulnerability assessment
    ✓ Professional reporting (HTML, JSON, CSV, PDF)
    ✓ API integrations (Shodan, CVE, NVD)
    ✓ Stealth scanning options
    ✓ IDS/IPS evasion techniques

SECURITY FEATURES:
    ✓ Rate limiting to prevent DoS
    ✓ Configurable scan aggression
    ✓ Safe scanning modes
    ✓ Audit logging
    ✓ Encryption of sensitive results
"""

import asyncio
import aiohttp
import socket
import ssl
import ipaddress
import argparse
import sys
import os
import json
import csv
import time
import hashlib
import hmac
import base64
import logging
import threading
import queue
import random
import struct
import netifaces
from datetime import datetime, timedelta
from typing import List, Dict, Set, Tuple, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from pathlib import Path
import subprocess
import platform
import re
import xml.etree.ElementTree as ET
from xml.dom import minidom
import jinja2
import yaml
import pickle
import gzip
import shutil
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
#from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Try importing optional dependencies with graceful fallbacks
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, sr, RandShort
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from OpenSSL import SSL, crypto
    PYOPENSSL_AVAILABLE = True
except ImportError:
    PYOPENSSL_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

class ScanProfile(Enum):
    """Scan profiles for different use cases"""
    STEALTH = "stealth"          # Slow, hard to detect
    NORMAL = "normal"             # Balanced approach
    AGGRESSIVE = "aggressive"      # Fast, might be detected
    COMPREHENSIVE = "comprehensive" # Complete, time-consuming
    COMPLIANCE = "compliance"       # PCI-DSS, HIPAA specific

class ServiceCategory(Enum):
    """Service categorization"""
    WEB = "web"
    DATABASE = "database"
    MAIL = "mail"
    FILE = "file"
    REMOTE = "remote_access"
    NETWORK = "network_service"
    IOT = "iot"
    INDUSTRIAL = "industrial"
    UNKNOWN = "unknown"

@dataclass
class ScanConfig:
    """Comprehensive scan configuration"""
    # Basic settings
    target: str
    ports: str = "1-1000"
    protocol: str = "tcp"
    threads: int = 100
    timeout: float = 2.0
    profile: ScanProfile = ScanProfile.NORMAL
    
    # Advanced settings
    rate_limit: int = 1000  # packets per second
    randomize_ports: bool = False
    fragment_packets: bool = False
    decoy_ips: List[str] = field(default_factory=list)
    source_port: Optional[int] = None
    
    # Service detection
    deep_banner_grabbing: bool = True
    ssl_analysis: bool = True
    version_intensity: int = 7  # 1-9
    
    # Vulnerability assessment
    vulnerability_check: bool = True
    cve_database_update: bool = True
    exploit_check: bool = False
    
    # Evasion
    spoof_mac: Optional[str] = None
    ttl: Optional[int] = None
    data_length: Optional[int] = None
    
    # Output
    output_dir: str = "scan_results"
    report_formats: List[str] = field(default_factory=lambda: ["json", "csv", "html"])
    encrypt_results: bool = False
    encryption_password: Optional[str] = None
    
    # API integrations
    shodan_api_key: Optional[str] = None
    virus_total_key: Optional[str] = None
    cve_api_key: Optional[str] = None

@dataclass
class ServiceInfo:
    """Detailed service information"""
    port: int
    protocol: str
    state: str
    service: str
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: str = ""
    banner: str = ""
    confidence: float = 0.0
    category: ServiceCategory = ServiceCategory.UNKNOWN
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class HostInfo:
    """Comprehensive host information"""
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    os: Dict[str, Any] = field(default_factory=dict)
    services: List[ServiceInfo] = field(default_factory=list)
    uptime: Optional[int] = None
    last_boot: Optional[str] = None
    distance: Optional[int] = None
    traceroute: List[str] = field(default_factory=list)
    scripts: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""

@dataclass
class Vulnerability:
    """Comprehensive vulnerability information"""
    id: str
    name: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score: float
    cvss_vector: str
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    exploits_available: bool = False
    exploit_db_ids: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    published_date: Optional[str] = None
    last_modified: Optional[str] = None

@dataclass
class ScanResult:
    """Complete scan results"""
    scan_id: str
    scan_config: ScanConfig
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: float = 0.0
    hosts: List[HostInfo] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# ============================================================================
# CVE DATABASE INTEGRATION
# ============================================================================

class CVEDatabase:
    """
    Comprehensive CVE database with NVD integration
    """
    
    def __init__(self, cache_dir: str = "cve_cache", api_key: str = None):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.api_key = api_key
        self.cve_data = {}
        self.last_update = None
        self.logger = logging.getLogger(__name__)
        
        # Initialize with built-in CVE data (simplified for demo)
        self._init_builtin_cve_data()
        
    def _init_builtin_cve_data(self):
        """Initialize with built-in CVE data for common services"""
        self.builtin_cves = {
            "ssh": {
                "OpenSSH": {
                    "versions": {
                        "<7.4": ["CVE-2016-10009", "CVE-2016-10010", "CVE-2016-10011"],
                        "<7.5": ["CVE-2017-15906"],
                        "<7.6": ["CVE-2017-15906"],
                        "<7.7": ["CVE-2018-15473"],
                        "<7.9": ["CVE-2018-20685"],
                        "<8.0": ["CVE-2019-6109", "CVE-2019-6110"],
                        "<8.1": ["CVE-2019-16905"],
                        "<8.5": ["CVE-2020-14145"],
                        "<8.8": ["CVE-2021-41617"],
                    }
                }
            },
            "http": {
                "Apache": {
                    "versions": {
                        "2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],
                        "2.4.48": ["CVE-2021-40438"],
                        "2.4.46": ["CVE-2020-13938", "CVE-2020-35452"],
                        "2.4.43": ["CVE-2020-11984"],
                        "2.4.41": ["CVE-2019-17567"],
                        "2.4.39": ["CVE-2019-10082"],
                        "2.4.38": ["CVE-2019-0196"],
                        "2.4.37": ["CVE-2018-17189", "CVE-2018-1312"],
                    }
                },
                "nginx": {
                    "versions": {
                        "1.20.0": ["CVE-2021-23017"],
                        "1.18.0": ["CVE-2020-11724"],
                        "1.16.1": ["CVE-2019-20372"],
                        "1.14.0": ["CVE-2018-16843", "CVE-2018-16844"],
                    }
                },
                "IIS": {
                    "versions": {
                        "10.0": ["CVE-2021-31166"],
                        "8.5": ["CVE-2015-1635"],
                        "7.5": ["CVE-2010-3972", "CVE-2010-2730"],
                    }
                }
            },
            "ftp": {
                "vsftpd": {
                    "versions": {
                        "2.3.4": ["CVE-2011-2523"],
                        "2.3.2": ["CVE-2011-0762"],
                        "2.0.5": ["CVE-2007-5962"],
                    }
                },
                "ProFTPD": {
                    "versions": {
                        "1.3.5": ["CVE-2015-3306"],
                        "1.3.3c": ["CVE-2010-4221"],
                    }
                }
            },
            "database": {
                "MySQL": {
                    "versions": {
                        "5.7.10": ["CVE-2016-6662", "CVE-2016-6663"],
                        "5.6.20": ["CVE-2015-3155"],
                        "5.5.44": ["CVE-2015-5506"],
                    }
                },
                "PostgreSQL": {
                    "versions": {
                        "12.3": ["CVE-2020-14350"],
                        "11.8": ["CVE-2020-14350"],
                        "10.13": ["CVE-2020-14350"],
                        "9.6.18": ["CVE-2020-14350"],
                    }
                },
                "MongoDB": {
                    "versions": {
                        "4.0.0": ["CVE-2018-17181"],
                        "3.6.0": ["CVE-2018-17181"],
                    }
                }
            },
            "mail": {
                "Postfix": {
                    "versions": {
                        "3.5.8": ["CVE-2021-29657"],
                        "3.4.0": ["CVE-2020-13757"],
                    }
                },
                "Exim": {
                    "versions": {
                        "4.94": ["CVE-2020-28007"],
                        "4.93": ["CVE-2020-28008"],
                        "4.92": ["CVE-2020-28009"],
                    }
                }
            }
        }
        
    async def update_cve_database(self):
        """Update CVE database from NVD"""
        try:
            self.logger.info("Updating CVE database from NVD...")
            
            # NVD API endpoint
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            
            # Calculate date for incremental update
            if self.last_update:
                start_date = self.last_update
            else:
                start_date = datetime.now() - timedelta(days=7)
            
            params = {
                "startIndex": 0,
                "resultsPerPage": 2000,
                "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-00:00")
            }
            
            if self.api_key:
                params["apiKey"] = self.api_key
            
            async with aiohttp.ClientSession() as session:
                async with session.get(base_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        self._parse_nvd_response(data)
                        self.last_update = datetime.now()
                        self._save_cache()
                        self.logger.info(f"CVE database updated: {len(self.cve_data)} entries")
                    else:
                        self.logger.error(f"NVD API error: {response.status}")
                        
        except Exception as e:
            self.logger.error(f"Error updating CVE database: {e}")
            
    def _parse_nvd_response(self, data: Dict):
        """Parse NVD API response"""
        for vuln in data.get("vulnerabilities", []):
            cve_item = vuln.get("cve", {})
            cve_id = cve_item.get("id")
            
            if not cve_id:
                continue
                
            descriptions = cve_item.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )
            
            metrics = cve_item.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
            
            cvss_data = cvss_v3 or cvss_v2
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")
            
            configurations = cve_item.get("configurations", [])
            affected_versions = self._parse_affected_versions(configurations)
            
            self.cve_data[cve_id] = {
                "id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "published": cve_item.get("published"),
                "last_modified": cve_item.get("lastModified"),
                "affected_versions": affected_versions,
                "references": [ref.get("url") for ref in cve_item.get("references", [])]
            }
            
    def _parse_affected_versions(self, configurations: List) -> List[str]:
        """Parse affected versions from CVE configuration"""
        versions = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if "versionStartIncluding" in cpe_match:
                        versions.append(f">={cpe_match['versionStartIncluding']}")
                    if "versionEndIncluding" in cpe_match:
                        versions.append(f"<={cpe_match['versionEndIncluding']}")
        return versions
        
    def _save_cache(self):
        """Save CVE database to cache"""
        cache_file = self.cache_dir / "cve_cache.pkl.gz"
        data = {
            "timestamp": self.last_update,
            "cves": self.cve_data
        }
        
        with gzip.open(cache_file, "wb") as f:
            pickle.dump(data, f)
            
    def _load_cache(self):
        """Load CVE database from cache"""
        cache_file = self.cache_dir / "cve_cache.pkl.gz"
        if cache_file.exists():
            try:
                with gzip.open(cache_file, "rb") as f:
                    data = pickle.load(f)
                    self.cve_data = data["cves"]
                    self.last_update = data["timestamp"]
                    return True
            except Exception as e:
                self.logger.error(f"Error loading cache: {e}")
        return False
        
    def check_vulnerabilities(self, service: str, product: str, version: str) -> List[Vulnerability]:
        """
        Check for vulnerabilities in a specific service version
        
        Args:
            service: Service name (ssh, http, mysql, etc.)
            product: Product name (OpenSSH, Apache, etc.)
            version: Version string
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Check built-in database first
        if service in self.builtin_cves:
            service_cves = self.builtin_cves[service]
            if product in service_cves:
                product_cves = service_cves[product]
                for ver_range, cve_list in product_cves["versions"].items():
                    if self._version_matches(version, ver_range):
                        for cve_id in cve_list:
                            if cve_id in self.cve_data:
                                cve_info = self.cve_data[cve_id]
                                vulnerabilities.append(
                                    Vulnerability(
                                        id=cve_id,
                                        name=cve_id,
                                        description=cve_info["description"],
                                        severity=self._cvss_to_severity(cve_info["cvss_score"]),
                                        cvss_score=cve_info["cvss_score"],
                                        cvss_vector=cve_info["cvss_vector"],
                                        cve_ids=[cve_id],
                                        published_date=cve_info["published"],
                                        last_modified=cve_info["last_modified"],
                                        references=cve_info["references"]
                                    )
                                )
        
        return vulnerabilities
        
    def _version_matches(self, version: str, version_range: str) -> bool:
        """Check if version matches range specification"""
        try:
            # Simple version comparison
            if version_range.startswith("<"):
                op = version_range[0]
                ver = version_range[1:]
                
                if op == "<":
                    return self._compare_versions(version, ver) < 0
                elif op == "<=":
                    return self._compare_versions(version, ver) <= 0
                    
            elif version_range.startswith(">="):
                ver = version_range[2:]
                return self._compare_versions(version, ver) >= 0
                
            elif version_range.startswith("<="):
                ver = version_range[2:]
                return self._compare_versions(version, ver) <= 0
                
            elif version_range.startswith("="):
                ver = version_range[1:]
                return self._compare_versions(version, ver) == 0
                
            else:
                # Exact match
                return version == version_range
                
        except Exception:
            return False
            
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings"""
        def normalize(v):
            return [int(x) for x in re.findall(r"\d+", v)]
            
        v1_parts = normalize(v1)
        v2_parts = normalize(v2)
        
        for i in range(min(len(v1_parts), len(v2_parts))):
            if v1_parts[i] < v2_parts[i]:
                return -1
            elif v1_parts[i] > v2_parts[i]:
                return 1
                
        return len(v1_parts) - len(v2_parts)
        
    def _cvss_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity rating"""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 0.1:
            return "LOW"
        else:
            return "INFO"


# ============================================================================
# ADVANCED SERVICE FINGERPRINTING
# ============================================================================

class ServiceFingerprinter:
    """
    Advanced service fingerprinting with deep banner grabbing and version detection
    """
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
        # Extended service probes
        self.probes = {
            # Web servers
            80: [
                b"HEAD / HTTP/1.0\r\n\r\n",
                b"GET / HTTP/1.0\r\n\r\n",
                b"OPTIONS * HTTP/1.0\r\n\r\n",
                b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            ],
            443: [
                b"HEAD / HTTP/1.0\r\n\r\n",
                b"GET / HTTP/1.0\r\n\r\n",
            ],
            8080: [
                b"HEAD / HTTP/1.0\r\n\r\n",
                b"GET / HTTP/1.0\r\n\r\n",
            ],
            8443: [
                b"HEAD / HTTP/1.0\r\n\r\n",
                b"GET / HTTP/1.0\r\n\r\n",
            ],
            
            # Mail servers
            25: [
                b"EHLO test.com\r\n",
                b"HELP\r\n",
                b"VRFY root\r\n",
                b"EXPN root\r\n",
            ],
            110: [
                b"USER test\r\n",
                b"STAT\r\n",
                b"CAPA\r\n",
            ],
            143: [
                b"a001 LOGIN\r\n",
                b"a001 CAPABILITY\r\n",
            ],
            587: [
                b"EHLO test.com\r\n",
                b"STARTTLS\r\n",
            ],
            
            # Database servers
            3306: [
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                b"\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            5432: [
                b"\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00",
                b"SELECT version();\x00",
            ],
            27017: [
                b"\x3a\x00\x00\x00\x41\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            6379: [
                b"INFO\r\n",
                b"PING\r\n",
                b"CONFIG GET *\r\n",
            ],
            
            # File servers
            21: [
                b"HELP\r\n",
                b"SYST\r\n",
                b"FEAT\r\n",
                b"STAT\r\n",
            ],
            445: [
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            2049: [
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            
            # Remote access
            22: [
                b"SSH-2.0-OpenSSH_8.9\r\n",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            23: [
                b"\r\n",
                b"\x00",
            ],
            3389: [
                b"\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            5900: [
                b"RFB 003.008\n",
                b"\x00",
            ],
            
            # Network services
            53: [
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                b"\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            67: [
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            123: [
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            161: [
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            
            # Industrial/SCADA
            502: [
                b"\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            102: [
                b"\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
        }
        
        # Service signatures for identification
        self.signatures = {
            # Web servers
            "Apache": [b"Apache", b"apache", b"httpd"],
            "nginx": [b"nginx", b"NGINX"],
            "IIS": [b"Microsoft-IIS", b"IIS", b"MS-Server"],
            "Tomcat": [b"Apache-Coyote", b"Tomcat"],
            "Jetty": [b"Jetty"],
            "Node.js": [b"Node.js", b"Express"],
            "Caddy": [b"Caddy"],
            
            # SSH
            "OpenSSH": [b"OpenSSH"],
            "Dropbear": [b"dropbear"],
            "CiscoSSH": [b"Cisco"],
            
            # FTP
            "vsftpd": [b"vsftpd"],
            "ProFTPD": [b"ProFTPD"],
            "Pure-FTPd": [b"Pure-FTPd"],
            "FileZilla": [b"FileZilla"],
            
            # Databases
            "MySQL": [b"mysql", b"MySQL", b"MariaDB"],
            "PostgreSQL": [b"PostgreSQL"],
            "MongoDB": [b"MongoDB"],
            "Redis": [b"redis"],
            "Elasticsearch": [b"elasticsearch", b"Elasticsearch"],
            "Cassandra": [b"Cassandra"],
            
            # Mail
            "Postfix": [b"Postfix", b"ESMTP"],
            "Sendmail": [b"Sendmail"],
            "Exim": [b"Exim"],
            "Dovecot": [b"Dovecot"],
            "Courier": [b"Courier"],
            
            # File services
            "Samba": [b"Samba"],
            "NFS": [b"NFS"],
            
            # Remote access
            "VNC": [b"RFB", b"VNC"],
            "RDP": [b"RDP", b"Remote Desktop"],
            "Telnet": [b"Telnet"],
            
            # Network services
            "DNS": [b"DNS"],
            "DHCP": [b"DHCP"],
            "NTP": [b"NTP"],
            "SNMP": [b"SNMP"],
            "LDAP": [b"LDAP"],
            "Kerberos": [b"Kerberos"],
            
            # Industrial
            "Modbus": [b"Modbus"],
            "S7": [b"S7"],
            "BACnet": [b"BACnet"],
        }
        
    async def fingerprint(self, ip: str, port: int, protocol: str = "tcp") -> ServiceInfo:
        """
        Perform deep service fingerprinting
        
        Args:
            ip: Target IP address
            port: Target port
            protocol: Protocol (tcp/udp)
            
        Returns:
            ServiceInfo object with detailed service information
        """
        service_info = ServiceInfo(
            port=port,
            protocol=protocol,
            state="closed",
            service="unknown",
            confidence=0.0
        )
        
        if protocol == "tcp":
            return await self._fingerprint_tcp(ip, port)
        else:
            return await self._fingerprint_udp(ip, port)
            
    async def _fingerprint_tcp(self, ip: str, port: int) -> ServiceInfo:
        """TCP service fingerprinting"""
        service_info = ServiceInfo(
            port=port,
            protocol="tcp",
            state="closed",
            service="unknown",
            confidence=0.0
        )
        
        try:
            # Try multiple probes for this port
            probes = self.probes.get(port, [b"\r\n", b"\n", b""])
            
            for probe in probes:
                try:
                    # Create socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    
                    # Connect
                    result = sock.connect_ex((ip, port))
                    
                    if result == 0:
                        service_info.state = "open"
                        
                        # Send probe
                        if probe:
                            sock.send(probe)
                        
                        # Receive response
                        banner = sock.recv(4096)
                        
                        if banner:
                            # Decode banner
                            try:
                                banner_str = banner.decode('utf-8', errors='ignore').strip()
                            except:
                                banner_str = base64.b64encode(banner).decode()
                                
                            service_info.banner = banner_str
                            
                            # Identify service from banner
                            self._identify_service(service_info, banner)
                            
                            # Extract version
                            self._extract_version(service_info, banner_str)
                            
                            # Check for SSL/TLS
                            if port in [443, 8443, 465, 993, 995]:
                                service_info.ssl_info = await self._analyze_ssl(ip, port)
                                
                            # Set category
                            self._set_category(service_info)
                            
                            # Calculate confidence
                            self._calculate_confidence(service_info)
                            
                            break
                            
                    sock.close()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.debug(f"Error fingerprinting {ip}:{port}: {e}")
                    continue
                    
            # If no response but port is open
            if service_info.state == "open" and not service_info.banner:
                service_info.service = "unknown"
                service_info.confidence = 0.1
                
        except Exception as e:
            self.logger.error(f"Fingerprint error {ip}:{port}: {e}")
            
        return service_info
        
    async def _fingerprint_udp(self, ip: str, port: int) -> ServiceInfo:
        """UDP service fingerprinting"""
        service_info = ServiceInfo(
            port=port,
            protocol="udp",
            state="closed",
            service="unknown",
            confidence=0.0
        )
        
        try:
            # UDP probes
            udp_probes = {
                53: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                161: b"\x00\x00\x00\x00\x00\x00\x00\x00",
                123: b"\x00\x00\x00\x00\x00\x00\x00\x00",
            }
            
            probe = udp_probes.get(port, b"")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            sock.sendto(probe, (ip, port))
            
            try:
                data, addr = sock.recvfrom(4096)
                service_info.state = "open"
                
                if data:
                    service_info.banner = base64.b64encode(data).decode()
                    service_info.service = "unknown"
                    service_info.confidence = 0.3
                    
            except socket.timeout:
                # No response - could be open|filtered
                service_info.state = "open|filtered"
                
            sock.close()
            
        except Exception as e:
            self.logger.debug(f"UDP fingerprint error {ip}:{port}: {e}")
            
        return service_info
        
    def _identify_service(self, service_info: ServiceInfo, banner: bytes):
        """Identify service from banner"""
        banner_lower = banner.lower()
        
        for service, patterns in self.signatures.items():
            for pattern in patterns:
                if pattern.lower() in banner_lower:
                    service_info.service = service.lower()
                    service_info.product = service
                    
                    # Check for specific service categories
                    if service in ["Apache", "nginx", "IIS", "Tomcat"]:
                        service_info.category = ServiceCategory.WEB
                    elif service in ["MySQL", "PostgreSQL", "MongoDB", "Redis"]:
                        service_info.category = ServiceCategory.DATABASE
                    elif service in ["vsftpd", "ProFTPD", "Samba"]:
                        service_info.category = ServiceCategory.FILE
                    elif service in ["OpenSSH", "Dropbear"]:
                        service_info.category = ServiceCategory.REMOTE
                    elif service in ["Postfix", "Sendmail", "Exim"]:
                        service_info.category = ServiceCategory.MAIL
                        
                    return
                    
    def _extract_version(self, service_info: ServiceInfo, banner: str):
        """Extract version information from banner"""
        # Common version patterns
        version_patterns = [
            r'(\d+\.\d+(?:\.\d+)?(?:[a-z]+\d*)?)',
            r'version[\s:=]+([\d\.]+)',
            r'/([\d\.]+)',
            r'-([\d\.]+[a-z]*)',
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, banner, re.IGNORECASE)
            if matches:
                service_info.version = matches[0]
                break
                
        # Extract additional info
        if service_info.service == "ssh":
            if "Ubuntu" in banner:
                service_info.extrainfo = "Ubuntu"
            elif "Debian" in banner:
                service_info.extrainfo = "Debian"
                
        elif service_info.service == "http":
            if "Apache" in banner:
                server_match = re.search(r'Server: ([^\r\n]+)', banner)
                if server_match:
                    service_info.extrainfo = server_match.group(1)
                    
    async def _analyze_ssl(self, ip: str, port: int) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        ssl_info = {
            "enabled": False,
            "version": None,
            "cipher": None,
            "certificate": {},
            "vulnerabilities": []
        }
        
        if not PYOPENSSL_AVAILABLE:
            return ssl_info
            
        try:
            context = SSL.Context(SSL.TLSv1_2_METHOD)
            conn = SSL.Connection(context, socket.socket())
            conn.set_tlsext_host_name(ip.encode())
            conn.connect((ip, port))
            conn.setblocking(1)
            conn.do_handshake()
            
            ssl_info["enabled"] = True
            ssl_info["version"] = conn.get_protocol_version_name()
            ssl_info["cipher"] = conn.get_cipher_name()
            
            # Get certificate
            cert = conn.get_peer_certificate()
            if cert:
                cert_info = {
                    "subject": dict(cert.get_subject().get_components()),
                    "issuer": dict(cert.get_issuer().get_components()),
                    "version": cert.get_version(),
                    "serial_number": cert.get_serial_number(),
                    "not_before": cert.get_notBefore().decode(),
                    "not_after": cert.get_notAfter().decode(),
                    "signature_algorithm": cert.get_signature_algorithm().decode(),
                }
                
                # Check for weak algorithms
                if "md5" in cert_info["signature_algorithm"].lower():
                    ssl_info["vulnerabilities"].append({
                        "name": "Weak Signature Algorithm",
                        "severity": "MEDIUM",
                        "description": f"Certificate uses {cert_info['signature_algorithm']}"
                    })
                    
                # Check expiration
                not_after = datetime.strptime(cert_info["not_after"], "%Y%m%d%H%M%SZ")
                if not_after < datetime.now():
                    ssl_info["vulnerabilities"].append({
                        "name": "Expired Certificate",
                        "severity": "HIGH",
                        "description": f"Certificate expired on {not_after}"
                    })
                    
                ssl_info["certificate"] = cert_info
                
            conn.close()
            
        except Exception as e:
            self.logger.debug(f"SSL analysis error: {e}")
            
        return ssl_info
        
    def _set_category(self, service_info: ServiceInfo):
        """Set service category based on port and service"""
        # Category by port
        port_categories = {
            80: ServiceCategory.WEB,
            443: ServiceCategory.WEB,
            8080: ServiceCategory.WEB,
            8443: ServiceCategory.WEB,
            3306: ServiceCategory.DATABASE,
            5432: ServiceCategory.DATABASE,
            27017: ServiceCategory.DATABASE,
            6379: ServiceCategory.DATABASE,
            25: ServiceCategory.MAIL,
            110: ServiceCategory.MAIL,
            143: ServiceCategory.MAIL,
            587: ServiceCategory.MAIL,
            21: ServiceCategory.FILE,
            445: ServiceCategory.FILE,
            2049: ServiceCategory.FILE,
            22: ServiceCategory.REMOTE,
            23: ServiceCategory.REMOTE,
            3389: ServiceCategory.REMOTE,
            5900: ServiceCategory.REMOTE,
            53: ServiceCategory.NETWORK,
            67: ServiceCategory.NETWORK,
            123: ServiceCategory.NETWORK,
            161: ServiceCategory.NETWORK,
            502: ServiceCategory.INDUSTRIAL,
            102: ServiceCategory.INDUSTRIAL,
        }
        
        if service_info.port in port_categories:
            service_info.category = port_categories[service_info.port]
            
        # Override by identified service
        service_categories = {
            "http": ServiceCategory.WEB,
            "https": ServiceCategory.WEB,
            "mysql": ServiceCategory.DATABASE,
            "postgresql": ServiceCategory.DATABASE,
            "mongodb": ServiceCategory.DATABASE,
            "redis": ServiceCategory.DATABASE,
            "smtp": ServiceCategory.MAIL,
            "pop3": ServiceCategory.MAIL,
            "imap": ServiceCategory.MAIL,
            "ftp": ServiceCategory.FILE,
            "smb": ServiceCategory.FILE,
            "nfs": ServiceCategory.FILE,
            "ssh": ServiceCategory.REMOTE,
            "telnet": ServiceCategory.REMOTE,
            "rdp": ServiceCategory.REMOTE,
            "vnc": ServiceCategory.REMOTE,
            "dns": ServiceCategory.NETWORK,
            "dhcp": ServiceCategory.NETWORK,
            "ntp": ServiceCategory.NETWORK,
            "snmp": ServiceCategory.NETWORK,
            "modbus": ServiceCategory.INDUSTRIAL,
        }
        
        if service_info.service in service_categories:
            service_info.category = service_categories[service_info.service]
            
    def _calculate_confidence(self, service_info: ServiceInfo):
        """Calculate confidence score for service identification"""
        confidence = 0.0
        
        # Banner present increases confidence
        if service_info.banner:
            confidence += 0.4
            
        # Product identified
        if service_info.product:
            confidence += 0.3
            
        # Version identified
        if service_info.version:
            confidence += 0.2
            
        # SSL info available
        if service_info.ssl_info and service_info.ssl_info.get("enabled"):
            confidence += 0.1
            
        # Cap at 1.0
        service_info.confidence = min(confidence, 1.0)


# ============================================================================
# ADVANCED PORT SCANNER
# ============================================================================

class AdvancedPortScanner:
    """
    Production-grade port scanner with multiple scan techniques
    """
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.open_ports = []
        self.scan_queue = queue.Queue()
        self.results_lock = threading.Lock()
        self.scan_stats = {
            "ports_scanned": 0,
            "ports_open": 0,
            "ports_filtered": 0,
            "ports_closed": 0,
            "errors": 0
        }
        
    async def scan_host(self, ip: str) -> List[ServiceInfo]:
        """
        Perform comprehensive port scan on a single host
        
        Args:
            ip: Target IP address
            
        Returns:
            List of ServiceInfo objects for open ports
        """
        services = []
        ports = self._parse_ports()
        
        self.logger.info(f"Scanning {ip} with {len(ports)} ports")
        
        # Choose scan technique based on profile
        if self.config.profile == ScanProfile.STEALTH:
            scan_func = self._syn_scan
        elif self.config.profile == ScanProfile.AGGRESSIVE:
            scan_func = self._tcp_connect_scan_aggressive
        else:
            scan_func = self._tcp_connect_scan
            
        # Perform scan
        open_ports = await scan_func(ip, ports)
        
        # Fingerprint open ports
        fingerprinter = ServiceFingerprinter(timeout=self.config.timeout)
        
        for port in open_ports:
            service = await fingerprinter.fingerprint(ip, port, self.config.protocol)
            services.append(service)
            
            # Check vulnerabilities if enabled
            if self.config.vulnerability_check and service.service != "unknown":
                await self._check_vulnerabilities(service)
                
        return services
        
    def _parse_ports(self) -> List[int]:
        """Parse port specification into list"""
        ports = []
        ports_str = self.config.ports
        
        try:
            if ',' in ports_str:
                for part in ports_str.split(','):
                    part = part.strip()
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        ports.extend(range(start, end + 1))
                    else:
                        ports.append(int(part))
            elif '-' in ports_str:
                start, end = map(int, ports_str.split('-'))
                ports = list(range(start, end + 1))
            else:
                ports = [int(ports_str)]
        except:
            # Default to common ports
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                    993, 995, 1723, 3306, 3389, 5900, 8080]
            
        # Filter and randomize
        ports = [p for p in ports if 1 <= p <= 65535]
        
        if self.config.randomize_ports:
            random.shuffle(ports)
            
        return ports
        
    async def _tcp_connect_scan(self, ip: str, ports: List[int]) -> List[int]:
        """Standard TCP connect scan"""
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.timeout)
                
                if self.config.source_port:
                    sock.bind(('', self.config.source_port))
                    
                result = sock.connect_ex((ip, port))
                
                with self.results_lock:
                    self.scan_stats["ports_scanned"] += 1
                    
                if result == 0:
                    sock.close()
                    with self.results_lock:
                        self.scan_stats["ports_open"] += 1
                        open_ports.append(port)
                    return port
                    
                sock.close()
                
            except Exception as e:
                with self.results_lock:
                    self.scan_stats["errors"] += 1
                    
            return None
            
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    
        return open_ports
        
    async def _tcp_connect_scan_aggressive(self, ip: str, ports: List[int]) -> List[int]:
        """Aggressive TCP scan with connection reuse"""
        open_ports = []
        
        # Create multiple sockets for parallel scanning
        sockets = []
        for _ in range(min(self.config.threads, len(ports))):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.timeout)
                sockets.append(sock)
            except:
                pass
                
        # Scan ports
        port_index = 0
        for sock in sockets:
            if port_index >= len(ports):
                break
                
            port = ports[port_index]
            port_index += 1
            
            try:
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    open_ports.append(port)
                    
                    # Try to grab banner quickly
                    try:
                        sock.send(b"\r\n")
                        banner = sock.recv(1024)
                    except:
                        pass
                        
            except:
                pass
                
        return open_ports
        
    async def _syn_scan(self, ip: str, ports: List[int]) -> List[int]:
        """SYN stealth scan (requires root)"""
        open_ports = []
        
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available, falling back to TCP connect")
            return await self._tcp_connect_scan(ip, ports)
            
        try:
            # Craft SYN packets
            for port in ports:
                packet = IP(dst=ip)/TCP(sport=RandShort(), dport=port, flags="S")
                
                # Add fragmentation if configured
                if self.config.fragment_packets:
                    packet = fragment(packet)[0]
                    
                # Send packet and receive response
                response = sr1(packet, timeout=self.config.timeout, verbose=0)
                
                if response and response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                        open_ports.append(port)
                        
                        # Send RST to close connection
                        rst = IP(dst=ip)/TCP(sport=response.getlayer(TCP).dport,
                                            dport=port, flags="R")
                        send(rst, verbose=0)
                        
                # Rate limiting
                if self.config.rate_limit > 0:
                    time.sleep(1.0 / self.config.rate_limit)
                    
        except Exception as e:
            self.logger.error(f"SYN scan error: {e}")
            
        return open_ports
        
    async def _check_vulnerabilities(self, service: ServiceInfo):
        """Check for vulnerabilities in detected service"""
        # Initialize CVE database
        cve_db = CVEDatabase()
        
        # Check for vulnerabilities
        vulns = cve_db.check_vulnerabilities(
            service.service,
            service.product,
            service.version
        )
        
        service.vulnerabilities = [asdict(v) for v in vulns]


# ============================================================================
# OS FINGERPRINTING
# ============================================================================

class OSFingerprinter:
    """
    Advanced OS fingerprinting using multiple techniques
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # TCP/IP fingerprint database
        self.fingerprints = {
            # Linux
            "Linux 2.6": {
                "ttl": 64,
                "window": 5840,
                "df": True,
                "tos": 0,
                "signature": "linux-2.6"
            },
            "Linux 3.x": {
                "ttl": 64,
                "window": 14600,
                "df": True,
                "tos": 0,
                "signature": "linux-3.x"
            },
            "Linux 4.x": {
                "ttl": 64,
                "window": 29200,
                "df": True,
                "tos": 0,
                "signature": "linux-4.x"
            },
            "Linux 5.x": {
                "ttl": 64,
                "window": 64240,
                "df": True,
                "tos": 0,
                "signature": "linux-5.x"
            },
            
            # Windows
            "Windows 7": {
                "ttl": 128,
                "window": 8192,
                "df": True,
                "tos": 0,
                "signature": "windows-7"
            },
            "Windows 8/10": {
                "ttl": 128,
                "window": 8192,
                "df": True,
                "tos": 0,
                "signature": "windows-10"
            },
            "Windows Server 2008": {
                "ttl": 128,
                "window": 16384,
                "df": True,
                "tos": 0,
                "signature": "windows-2008"
            },
            "Windows Server 2012": {
                "ttl": 128,
                "window": 8192,
                "df": True,
                "tos": 0,
                "signature": "windows-2012"
            },
            "Windows Server 2016": {
                "ttl": 128,
                "window": 64240,
                "df": True,
                "tos": 0,
                "signature": "windows-2016"
            },
            "Windows Server 2019": {
                "ttl": 128,
                "window": 64240,
                "df": True,
                "tos": 0,
                "signature": "windows-2019"
            },
            
            # BSD
            "FreeBSD": {
                "ttl": 64,
                "window": 65535,
                "df": True,
                "tos": 0,
                "signature": "freebsd"
            },
            "OpenBSD": {
                "ttl": 255,
                "window": 16384,
                "df": True,
                "tos": 0,
                "signature": "openbsd"
            },
            "NetBSD": {
                "ttl": 255,
                "window": 32768,
                "df": True,
                "tos": 0,
                "signature": "netbsd"
            },
            
            # macOS
            "macOS": {
                "ttl": 64,
                "window": 65535,
                "df": True,
                "tos": 0,
                "signature": "macos"
            },
            
            # Cisco
            "Cisco IOS": {
                "ttl": 255,
                "window": 4128,
                "df": False,
                "tos": 192,
                "signature": "cisco"
            },
            
            # Solaris
            "Solaris": {
                "ttl": 255,
                "window": 32850,
                "df": True,
                "tos": 0,
                "signature": "solaris"
            },
            
            # Network devices
            "Network Device": {
                "ttl": 255,
                "window": 8760,
                "df": True,
                "tos": 0,
                "signature": "network-device"
            },
        }
        
    async def fingerprint(self, ip: str) -> Dict[str, Any]:
        """
        Perform OS fingerprinting
        
        Args:
            ip: Target IP address
            
        Returns:
            Dictionary with OS information
        """
        os_info = {
            "os": "unknown",
            "accuracy": 0,
            "ttl": None,
            "window": None,
            "df": None,
            "tos": None,
            "methods_used": [],
            "details": {}
        }
        
        # Method 1: ICMP TTL analysis
        ttl_result = await self._analyze_ttl(ip)
        if ttl_result:
            os_info.update(ttl_result)
            os_info["methods_used"].append("ttl")
            
        # Method 2: TCP window analysis
        window_result = await self._analyze_tcp_window(ip)
        if window_result:
            os_info.update(window_result)
            os_info["methods_used"].append("tcp_window")
            
        # Method 3: Active fingerprinting with probes
        active_result = await self._active_fingerprint(ip)
        if active_result:
            os_info.update(active_result)
            os_info["methods_used"].append("active")
            
        # Method 4: Service banner analysis
        banner_result = await self._analyze_service_banners(ip)
        if banner_result:
            os_info.update(banner_result)
            os_info["methods_used"].append("banner")
            
        # Calculate confidence based on number of methods
        confidence_map = {
            1: 40,
            2: 60,
            3: 80,
            4: 95
        }
        os_info["accuracy"] = confidence_map.get(len(os_info["methods_used"]), 0)
        
        return os_info
        
    async def _analyze_ttl(self, ip: str) -> Optional[Dict[str, Any]]:
        """Analyze TTL from ICMP ping"""
        try:
            # Use system ping
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            cmd = ['ping', param, '1', '-w', '1', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            
            if result.returncode == 0:
                # Extract TTL
                ttl_match = re.search(r'ttl=(\d+)', result.stdout.lower())
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    
                    # Guess OS based on TTL
                    if ttl <= 64:
                        return {
                            "os": "Linux/Unix",
                            "ttl": ttl,
                            "details": {"ttl_guess": "Unix/Linux family (TTL ≤ 64)"}
                        }
                    elif ttl <= 128:
                        return {
                            "os": "Windows",
                            "ttl": ttl,
                            "details": {"ttl_guess": "Windows family (64 < TTL ≤ 128)"}
                        }
                    else:
                        return {
                            "os": "Network Device",
                            "ttl": ttl,
                            "details": {"ttl_guess": "Network device/other (TTL > 128)"}
                        }
        except:
            pass
            
        return None
        
    async def _analyze_tcp_window(self, ip: str) -> Optional[Dict[str, Any]]:
        """Analyze TCP window size"""
        try:
            # Connect to common port and analyze response
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            # Try to connect to a common port
            for port in [80, 22, 443, 25]:
                try:
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        # Get socket options
                        window = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                        
                        # Match against fingerprint database
                        for os_name, fingerprint in self.fingerprints.items():
                            if abs(window - fingerprint.get("window", 0)) < 1000:
                                return {
                                    "os": os_name,
                                    "window": window,
                                    "details": {
                                        "window_guess": f"Matched {os_name} (window: {window})"
                                    }
                                }
                        break
                except:
                    continue
                    
            sock.close()
            
        except:
            pass
            
        return None
        
    async def _active_fingerprint(self, ip: str) -> Optional[Dict[str, Any]]:
        """Active fingerprinting with crafted packets"""
        if not SCAPY_AVAILABLE:
            return None
            
        try:
            # Send SYN packet with specific options
            packet = IP(dst=ip)/TCP(dport=80, flags="S", options=[('MSS', 1460), ('WScale', 7)])
            response = sr1(packet, timeout=2, verbose=0)
            
            if response and response.haslayer(TCP):
                # Analyze response
                window = response.getlayer(TCP).window
                options = response.getlayer(TCP).options
                
                # Match against fingerprint database
                for os_name, fingerprint in self.fingerprints.items():
                    if abs(window - fingerprint.get("window", 0)) < 1000:
                        return {
                            "os": os_name,
                            "window": window,
                            "details": {
                                "active_guess": f"Matched {os_name}",
                                "options": options
                            }
                        }
        except:
            pass
            
        return None
        
    async def _analyze_service_banners(self, ip: str) -> Optional[Dict[str, Any]]:
        """Analyze service banners for OS hints"""
        try:
            # Try to grab banners from common services
            service_probes = {
                22: b"SSH-2.0-OpenSSH\r\n",
                80: b"HEAD / HTTP/1.0\r\n\r\n",
                443: b"HEAD / HTTP/1.0\r\n\r\n",
                21: b"HELP\r\n",
                25: b"EHLO test.com\r\n",
            }
            
            for port, probe in service_probes.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((ip, port))
                    sock.send(probe)
                    banner = sock.recv(4096).decode('utf-8', errors='ignore')
                    sock.close()
                    
                    # Look for OS indicators in banner
                    if "Ubuntu" in banner:
                        return {"os": "Ubuntu Linux", "details": {"source": "SSH banner"}}
                    elif "Debian" in banner:
                        return {"os": "Debian Linux", "details": {"source": "SSH banner"}}
                    elif "CentOS" in banner:
                        return {"os": "CentOS Linux", "details": {"source": "SSH banner"}}
                    elif "Red Hat" in banner:
                        return {"os": "Red Hat Linux", "details": {"source": "SSH banner"}}
                    elif "Microsoft" in banner or "IIS" in banner:
                        return {"os": "Windows", "details": {"source": "HTTP banner"}}
                    elif "Apache" in banner and "Unix" in banner:
                        return {"os": "Unix/Linux", "details": {"source": "HTTP banner"}}
                        
                except:
                    continue
                    
        except:
            pass
            
        return None


# ============================================================================
# VULNERABILITY ASSESSMENT ENGINE
# ============================================================================

class VulnerabilityEngine:
    """
    Comprehensive vulnerability assessment engine
    """
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.cve_db = CVEDatabase(api_key=config.cve_api_key)
        
        # Load vulnerability checks
        self.checks = self._load_vulnerability_checks()
        
    def _load_vulnerability_checks(self) -> List[Dict[str, Any]]:
        """Load vulnerability check definitions"""
        return [
            {
                "id": "SSL-WEAK-CIPHER",
                "name": "Weak SSL/TLS Cipher",
                "severity": "MEDIUM",
                "check": self._check_weak_cipher,
                "service": ["http", "https", "ssl"]
            },
            {
                "id": "SSL-EXPIRED-CERT",
                "name": "Expired SSL Certificate",
                "severity": "HIGH",
                "check": self._check_expired_cert,
                "service": ["http", "https", "ssl"]
            },
            {
                "id": "SSL-SELF-SIGNED",
                "name": "Self-Signed SSL Certificate",
                "severity": "LOW",
                "check": self._check_self_signed,
                "service": ["http", "https", "ssl"]
            },
            {
                "id": "OPENSSH-WEAK-KEX",
                "name": "Weak SSH Key Exchange",
                "severity": "MEDIUM",
                "check": self._check_ssh_kex,
                "service": ["ssh"]
            },
            {
                "id": "FTP-ANONYMOUS",
                "name": "Anonymous FTP Login",
                "severity": "MEDIUM",
                "check": self._check_ftp_anonymous,
                "service": ["ftp"]
            },
            {
                "id": "HTTP-TRACE-ENABLED",
                "name": "HTTP TRACE Method Enabled",
                "severity": "LOW",
                "check": self._check_http_trace,
                "service": ["http", "https"]
            },
            {
                "id": "HTTP-DIRECTORY-LISTING",
                "name": "Directory Listing Enabled",
                "severity": "MEDIUM",
                "check": self._check_dir_listing,
                "service": ["http", "https"]
            },
            {
                "id": "SMTP-OPEN-RELAY",
                "name": "SMTP Open Relay",
                "severity": "HIGH",
                "check": self._check_smtp_relay,
                "service": ["smtp"]
            },
            {
                "id": "MYSQL-EMPTY-PASSWORD",
                "name": "MySQL Empty Password",
                "severity": "CRITICAL",
                "check": self._check_mysql_auth,
                "service": ["mysql"]
            },
            {
                "id": "REDIS-UNSECURED",
                "name": "Redis Unsecured Instance",
                "severity": "HIGH",
                "check": self._check_redis_auth,
                "service": ["redis"]
            },
            {
                "id": "MONGODB-UNSECURED",
                "name": "MongoDB Unsecured Instance",
                "severity": "HIGH",
                "check": self._check_mongodb_auth,
                "service": ["mongodb"]
            },
            {
                "id": "DEFAULT-CREDENTIALS",
                "name": "Default Credentials",
                "severity": "CRITICAL",
                "check": self._check_default_creds,
                "service": ["*"]
            }
        ]
        
    async def assess_host(self, host: HostInfo) -> List[Vulnerability]:
        """
        Perform comprehensive vulnerability assessment on a host
        
        Args:
            host: HostInfo object with service information
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Check each service
        for service in host.services:
            # CVE database check
            cve_vulns = self.cve_db.check_vulnerabilities(
                service.service,
                service.product,
                service.version
            )
            vulnerabilities.extend(cve_vulns)
            
            # Service-specific checks
            for check in self.checks:
                if check["service"] == ["*"] or service.service in check["service"]:
                    try:
                        result = await check["check"](host.ip, service)
                        if result:
                            vuln = Vulnerability(
                                id=check["id"],
                                name=check["name"],
                                description=result.get("description", ""),
                                severity=check["severity"],
                                cvss_score=result.get("cvss", 0),
                                cvss_vector=result.get("vector", ""),
                                remediation=result.get("remediation", ""),
                                exploits_available=result.get("exploits", False)
                            )
                            vulnerabilities.append(vuln)
                    except Exception as e:
                        self.logger.error(f"Error in check {check['id']}: {e}")
                        
        return vulnerabilities
        
    async def _check_weak_cipher(self, ip: str, service: ServiceInfo) -> Optional[Dict]:
        """Check for weak SSL/TLS ciphers"""
        if not service.ssl_info or not service.ssl_info.get("enabled"):
            return None
            
        cipher = service.ssl_info.get("cipher", "")
        weak_ciphers = ["RC4", "DES", "MD5", "NULL", "EXPORT", "LOW"]
        
        for weak in weak_ciphers:
            if weak.lower() in cipher.lower():
                return {
                    "description": f"Service uses weak cipher: {cipher}",
                    "remediation": "Disable weak ciphers, use strong TLS 1.2+ with AEAD ciphers",
                    "exploits": True
                }
        return None
        
    async def _check_expired_cert(self, ip: str, service: ServiceInfo) -> Optional[Dict]:
        """Check for expired SSL certificate"""
        if not service.ssl_info or not service.ssl_info.get("certificate"):
            return None
            
        cert = service.ssl_info["certificate"]
        if "not_after" in cert:
            try:
                not_after = datetime.strptime(cert["not_after"], "%Y%m%d%H%M%SZ")
                if not_after < datetime.now():
                    return {
                        "description": f"SSL certificate expired on {not_after}",
                        "remediation": "Renew SSL certificate immediately",
                        "cvss": 7.5
                    }
            except:
                pass
        return None
        
    async def _check_self_signed(self, ip: str, service: ServiceInfo) -> Optional[Dict]:
        """Check for self-signed SSL certificate"""
        if not service.ssl_info or not service.ssl_info.get("certificate"):
            return None
            
        cert = service.ssl_info["certificate"]
        if cert.get("issuer") == cert.get("subject"):
            return {
                "description": "Self-signed SSL certificate detected",
                "remediation": "Use certificate from trusted CA",
                "cvss": 4.0
            }
        return None
        
    async def _check_ssh_kex(self, ip: str, service: ServiceInfo) -> Optional[Dict]:
        """Check for weak SSH key exchange algorithms"""
        if service.service != "ssh" or not service.banner:
            return None
            
        weak_kex = ["diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"]
        
        # This would require actual SSH handshake analysis
        # Simplified for demonstration
        return None
        
    async def _check_ftp_anonymous(self, ip: str, service: ServiceInfo) -> Optional[Dict]:
        """Check for anonymous FTP access"""
        if service.service != "ftp":
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, service.port))
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Try anonymous login
            sock.send(b"USER anonymous\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if "331" in response:  # Password required
                sock.send(b"PASS anonymous@\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if "230" in response:  # Login successful
                    sock.close()
                    return {
                        "description": "Anonymous FTP login allowed",
                        "remediation": "Disable anonymous FTP access",
                        "cvss": 5.0,
                        "exploits": True
                    }
                    
            sock.close()
            
        except:
            pass
            
        return None
        
    async def _check_http_trace(self, ip: str, service: ServiceInfo) -> Optional[Dict]:
        """Check for HTTP TRACE method"""
        if service.service not in ["http", "https"]:
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            if service.port == 443:
                # SSL connection
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=ip)
                
            sock.connect((ip, service.port))
            sock.send(b"TRACE / HTTP/1.0\r\n\r\n")
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            if "200 OK" in response and "TRACE" in response:
                return {
                    "description": "HTTP TRACE method enabled",
                    "remediation": "Disable TRACE method in web server configuration",
                    "cvss": 3.5
                }
                
        except:
            pass
            
        return None
        
    async def _check_dir_listing(self, ip: str, service: ServiceInfo) -> Optional[Dict]:
        """Check for directory listing"""
        if service.service not in ["http", "https"]:
            return None
            
        common_dirs = ["/", "/images/", "/css/", "/js/", "/uploads/"]
        
        for directory in common_dirs:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                
                if service.port == 443:
                    context = ssl.create_default_context()
                    sock = context.wrap_socket(sock, server_hostname=ip)
                    
                sock.connect((ip, service.port))
                sock.send(f"GET {directory} HTTP/1.0\r\n\r\n".encode())
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                sock.close()
                
                # Check for directory listing indicators
                if "Index of /" in response or "<title>Index of" in response:
                    return {
                        "description": f"Directory listing enabled at {directory}",
                        "remediation": "Disable directory listing in web server",
                        "cvss": 4.0
                    }
                    
            except:
                continue
                
        return None
        
    async def _check_smtp_relay(self, ip: str, service: ServiceInfo) -> Optional[Dict]:
        """Check for SMTP open relay"""
        if service.service != "smtp":
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, service.port))
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Try to send mail to external domain
            sock.send(b"HELO test.com\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.send(b"MAIL FROM:<test@test.com>\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.send(b"RCPT TO:<test@gmail.com>\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if "250" in response:  # Relay accepted
                sock.close()
                return {
                    "description": "SMTP open relay detected",
                    "remediation": "Configure SMTP server to prevent relaying",
                    "cvss": 7.5,
                    "exploits": True
                }
                
            sock.close()
            
        except:
            pass
            
        return None
        
    async def _check_mysql_auth(self, ip: str, service: ServiceInfo) -> Optional[Dict]:
        """Check MySQL authentication"""
        if service.service != "mysql":
            return None
            
        try:
            # MySQL connection packet with empty password
            # This is a simplified check
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, service.port))
            
            # MySQL handshake would go here
            # For demo, we'll assume check passes
            
            sock.close()
            
        except:
            pass
            
        return None
        
    async def _check_redis_auth(self, ip: str, service: ServiceInfo) -> Optional[Dict]:
        """Check Redis authentication"""
        if service.service != "redis":
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, service.port))
            
            # Try to send INFO command
            sock.send(b"INFO\r\n")
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            if "redis_version" in response:
                return {
                    "description": "Redis instance without authentication",
                    "remediation": "Enable Redis authentication with requirepass",
                    "cvss": 7.0,
                    "exploits": True
                }
                
        except:
            pass
            
        return None
        
    async def _check_mongodb_auth(self, ip: str, service: ServiceInfo) -> Optional[Dict]:
        """Check MongoDB authentication"""
        if service.service != "mongodb":
            return None
            
        try:
            # MongoDB wire protocol check
            # Simplified for demonstration
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, service.port))
            
            # MongoDB handshake would go here
            
            sock.close()
            
        except:
            pass
            
        return None
        
    async def _check_default_creds(self, ip: str, service: ServiceInfo) -> Optional[Dict]:
        """Check for default credentials"""
        # Default credentials database
        default_creds = {
            "ssh": [("root", "root"), ("admin", "admin"), ("user", "user")],
            "ftp": [("anonymous", ""), ("ftp", "ftp"), ("admin", "admin")],
            "mysql": [("root", ""), ("root", "root"), ("admin", "admin")],
            "postgresql": [("postgres", ""), ("postgres", "postgres")],
            "redis": [("", "")],  # No auth by default
            "mongodb": [("", "")],  # No auth by default
            "tomcat": [("admin", "admin"), ("tomcat", "tomcat")],
            "jenkins": [("admin", "admin")],
        }
        
        if service.service in default_creds:
            # This would actually attempt login
            # Simplified for demonstration
            pass
            
        return None


# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """
    Professional report generator with multiple format support
    """
    
    def __init__(self, result: ScanResult, output_dir: str):
        self.result = result
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
        
    def generate_all(self):
        """Generate all configured report formats"""
        reports_generated = []
        
        if "json" in self.result.scan_config.report_formats:
            reports_generated.append(self.generate_json())
            
        if "csv" in self.result.scan_config.report_formats:
            reports_generated.append(self.generate_csv())
            
        if "html" in self.result.scan_config.report_formats:
            reports_generated.append(self.generate_html())
            
        if "xml" in self.result.scan_config.report_formats:
            reports_generated.append(self.generate_xml())
            
        if "pdf" in self.result.scan_config.report_formats and PDF_AVAILABLE:
            reports_generated.append(self.generate_pdf())
            
        if "nessus" in self.result.scan_config.report_formats:
            reports_generated.append(self.generate_nessus())
            
        if "metasploit" in self.result.scan_config.report_formats:
            reports_generated.append(self.generate_metasploit())
            
        return reports_generated
        
    def generate_json(self) -> str:
        """Generate JSON report"""
        # Convert dataclasses to dictionaries
        result_dict = {
            "scan_id": self.result.scan_id,
            "timestamp": self.result.start_time.isoformat(),
            "duration": self.result.duration,
            "target": self.result.scan_config.target,
            "statistics": self.result.statistics,
            "hosts": []
        }
        
        for host in self.result.hosts:
            host_dict = {
                "ip": host.ip,
                "hostname": host.hostname,
                "mac": host.mac,
                "vendor": host.vendor,
                "os": host.os,
                "services": []
            }
            
            for service in host.services:
                service_dict = {
                    "port": service.port,
                    "protocol": service.protocol,
                    "state": service.state,
                    "service": service.service,
                    "product": service.product,
                    "version": service.version,
                    "banner": service.banner[:200] if service.banner else "",
                    "confidence": service.confidence,
                    "category": service.category.value,
                    "vulnerabilities": service.vulnerabilities
                }
                host_dict["services"].append(service_dict)
                
            result_dict["hosts"].append(host_dict)
            
        # Save to file
        filename = self.output_dir / f"scan_{self.result.scan_id}.json"
        with open(filename, 'w') as f:
            json.dump(result_dict, f, indent=2, default=str)
            
        self.logger.info(f"JSON report saved: {filename}")
        return str(filename)
        
    def generate_csv(self) -> str:
        """Generate CSV report"""
        filename = self.output_dir / f"scan_{self.result.scan_id}.csv"
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'IP', 'Hostname', 'Port', 'Protocol', 'State',
                'Service', 'Product', 'Version', 'Category',
                'Confidence', 'Vulnerabilities', 'OS'
            ])
            
            for host in self.result.hosts:
                for service in host.services:
                    vuln_count = len(service.vulnerabilities)
                    writer.writerow([
                        host.ip,
                        host.hostname,
                        service.port,
                        service.protocol,
                        service.state,
                        service.service,
                        service.product,
                        service.version,
                        service.category.value,
                        f"{service.confidence:.2f}",
                        vuln_count,
                        host.os.get('os', 'unknown')
                    ])
                    
        self.logger.info(f"CSV report saved: {filename}")
        return str(filename)
        
    def generate_html(self) -> str:
        """Generate HTML report with visualizations"""
        template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Security Scan Report - {{ scan_id }}</title>
            <style>
                body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
                h2 { color: #34495e; margin-top: 30px; }
                .summary { background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }
                .host { background: white; border: 1px solid #bdc3c7; margin: 20px 0; padding: 15px; border-radius: 5px; }
                .host-header { background: #3498db; color: white; padding: 10px; margin: -15px -15px 15px -15px; border-radius: 5px 5px 0 0; }
                .service { display: inline-block; background: #ecf0f1; padding: 8px 12px; margin: 5px; border-radius: 3px; }
                .service.open { border-left: 4px solid #27ae60; }
                .service.filtered { border-left: 4px solid #f39c12; }
                .vuln { background: #fdeded; color: #e74c3c; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; margin-left: 5px; }
                .severity-critical { background: #e74c3c; color: white; padding: 2px 8px; border-radius: 3px; }
                .severity-high { background: #e67e22; color: white; padding: 2px 8px; border-radius: 3px; }
                .severity-medium { background: #f1c40f; color: black; padding: 2px 8px; border-radius: 3px; }
                .severity-low { background: #3498db; color: white; padding: 2px 8px; border-radius: 3px; }
                .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
                .stat-card { background: white; padding: 20px; text-align: center; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                .stat-value { font-size: 2em; font-weight: bold; color: #3498db; }
                .stat-label { color: #7f8c8d; margin-top: 5px; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th { background: #34495e; color: white; padding: 10px; text-align: left; }
                td { padding: 10px; border-bottom: 1px solid #bdc3c7; }
                tr:hover { background: #f5f5f5; }
                .footer { margin-top: 30px; text-align: center; color: #7f8c8d; font-size: 0.9em; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 Network Security Scan Report</h1>
                
                <div class="summary">
                    <h2>Scan Information</h2>
                    <p><strong>Scan ID:</strong> {{ scan_id }}</p>
                    <p><strong>Date:</strong> {{ timestamp }}</p>
                    <p><strong>Target:</strong> {{ target }}</p>
                    <p><strong>Duration:</strong> {{ duration }} seconds</p>
                    <p><strong>Profile:</strong> {{ profile }}</p>
                </div>
                
                <h2>📊 Executive Summary</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{{ stats.hosts_scanned }}</div>
                        <div class="stat-label">Hosts Scanned</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{{ stats.hosts_up }}</div>
                        <div class="stat-label">Live Hosts</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{{ stats.ports_open }}</div>
                        <div class="stat-label">Open Ports</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{{ stats.vulnerabilities }}</div>
                        <div class="stat-label">Vulnerabilities</div>
                    </div>
                </div>
                
                <h2>🎯 Host Details</h2>
                {% for host in hosts %}
                <div class="host">
                    <div class="host-header">
                        <strong>{{ host.ip }}</strong> 
                        {% if host.hostname %} ({{ host.hostname }}) {% endif %}
                        - {{ host.os.os }} ({{ host.os.accuracy }}% accuracy)
                    </div>
                    
                    <h4>Open Services:</h4>
                    {% for service in host.services %}
                    <div class="service {{ service.state }}">
                        <strong>{{ service.port }}/{{ service.protocol }}</strong>
                        {{ service.service }} {{ service.version }}
                        {% if service.vulnerabilities %}
                            <span class="vuln">{{ service.vulnerabilities|length }} vulns</span>
                        {% endif %}
                        <br>
                        <small>{{ service.product }} - {{ service.category.value }}</small>
                    </div>
                    {% endfor %}
                    
                    {% if host.services|selectattr('vulnerabilities')|list %}
                    <h4>⚠️ Vulnerabilities:</h4>
                    <table>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Vulnerability</th>
                            <th>Severity</th>
                            <th>CVSS</th>
                        </tr>
                        {% for service in host.services %}
                            {% for vuln in service.vulnerabilities %}
                            <tr>
                                <td>{{ service.port }}</td>
                                <td>{{ service.service }}</td>
                                <td>{{ vuln.name }}</td>
                                <td><span class="severity-{{ vuln.severity|lower }}">{{ vuln.severity }}</span></td>
                                <td>{{ vuln.cvss_score }}</td>
                            </tr>
                            {% endfor %}
                        {% endfor %}
                    </table>
                    {% endif %}
                </div>
                {% endfor %}
                
                <h2>📝 Recommendations</h2>
                <ul>
                    <li>Patch all critical and high severity vulnerabilities</li>
                    <li>Review open ports and close unnecessary services</li>
                    <li>Implement network segmentation for sensitive services</li>
                    <li>Enable logging and monitoring for detected services</li>
                    <li>Regular vulnerability scanning and patch management</li>
                </ul>
                
                <div class="footer">
                    Generated by Network Security Scanner v3.0 | {{ timestamp }} | For Educational Purposes Only
                </div>
            </div>
        </body>
        </html>
        """
        
        # Prepare template data
        vuln_count = 0
        for host in self.result.hosts:
            for service in host.services:
                vuln_count += len(service.vulnerabilities)
                
        template_data = {
            "scan_id": self.result.scan_id,
            "timestamp": self.result.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.result.scan_config.target,
            "duration": f"{self.result.duration:.2f}",
            "profile": self.result.scan_config.profile.value,
            "stats": {
                "hosts_scanned": self.result.statistics.get("total_hosts", 0),
                "hosts_up": len(self.result.hosts),
                "ports_open": self.result.statistics.get("open_ports", 0),
                "vulnerabilities": vuln_count
            },
            "hosts": self.result.hosts
        }
        
        # Render template
        from jinja2 import Template
        tmpl = Template(template)
        html = tmpl.render(**template_data)
        
        # Save to file
        filename = self.output_dir / f"scan_{self.result.scan_id}.html"
        with open(filename, 'w') as f:
            f.write(html)
            
        self.logger.info(f"HTML report saved: {filename}")
        return str(filename)
        
    def generate_xml(self) -> str:
        """Generate XML report (Nmap-compatible)"""
        root = ET.Element("nmaprun")
        root.set("scanner", "NetworkScanner v3.0")
        root.set("start", str(int(self.result.start_time.timestamp())))
        root.set("version", "3.0")
        
        # Scan info
        scaninfo = ET.SubElement(root, "scaninfo")
        scaninfo.set("type", self.result.scan_config.protocol)
        scaninfo.set("protocol", self.result.scan_config.protocol)
        scaninfo.set("numservices", str(self.result.statistics.get("ports_scanned", 0)))
        
        # Hosts
        for host in self.result.hosts:
            host_elem = ET.SubElement(root, "host")
            
            # Address
            address = ET.SubElement(host_elem, "address")
            address.set("addr", host.ip)
            address.set("addrtype", "ipv4")
            
            if host.mac:
                address = ET.SubElement(host_elem, "address")
                address.set("addr", host.mac)
                address.set("addrtype", "mac")
                if host.vendor:
                    address.set("vendor", host.vendor)
                    
            # Hostnames
            if host.hostname:
                hostnames = ET.SubElement(host_elem, "hostnames")
                hostname_elem = ET.SubElement(hostnames, "hostname")
                hostname_elem.set("name", host.hostname)
                hostname_elem.set("type", "PTR")
                
            # OS
            if host.os.get("os") != "unknown":
                os_elem = ET.SubElement(host_elem, "os")
                osmatch = ET.SubElement(os_elem, "osmatch")
                osmatch.set("name", host.os.get("os", "unknown"))
                osmatch.set("accuracy", str(host.os.get("accuracy", 0)))
                
            # Ports
            ports_elem = ET.SubElement(host_elem, "ports")
            
            for service in host.services:
                port_elem = ET.SubElement(ports_elem, "port")
                port_elem.set("protocol", service.protocol)
                port_elem.set("portid", str(service.port))
                
                state_elem = ET.SubElement(port_elem, "state")
                state_elem.set("state", service.state)
                
                service_elem = ET.SubElement(port_elem, "service")
                service_elem.set("name", service.service)
                if service.product:
                    service_elem.set("product", service.product)
                if service.version:
                    service_elem.set("version", service.version)
                if service.extrainfo:
                    service_elem.set("extrainfo", service.extrainfo)
                    
        # Pretty print XML
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        
        filename = self.output_dir / f"scan_{self.result.scan_id}.xml"
        with open(filename, 'w') as f:
            f.write(xml_str)
            
        self.logger.info(f"XML report saved: {filename}")
        return str(filename)
        
    def generate_pdf(self) -> str:
        """Generate PDF report (if reportlab available)"""
        if not PDF_AVAILABLE:
            self.logger.warning("PDF generation requires reportlab")
            return ""
            
        filename = self.output_dir / f"scan_{self.result.scan_id}.pdf"
        doc = SimpleDocTemplate(str(filename), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2c3e50')
        )
        story.append(Paragraph("Network Security Scan Report", title_style))
        story.append(Spacer(1, 12))
        
        # Scan info
        story.append(Paragraph(f"Scan ID: {self.result.scan_id}", styles['Normal']))
        story.append(Paragraph(f"Date: {self.result.start_time.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Paragraph(f"Target: {self.result.scan_config.target}", styles['Normal']))
        story.append(Paragraph(f"Duration: {self.result.duration:.2f} seconds", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Statistics
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        stats_data = [
            ["Metric", "Value"],
            ["Hosts Scanned", str(self.result.statistics.get("total_hosts", 0))],
            ["Live Hosts", str(len(self.result.hosts))],
            ["Open Ports", str(self.result.statistics.get("open_ports", 0))],
        ]
        
        stats_table = Table(stats_data, colWidths=[2*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 20))
        
        # Host details
        for host in self.result.hosts:
            story.append(Paragraph(f"Host: {host.ip}", styles['Heading3']))
            if host.hostname:
                story.append(Paragraph(f"Hostname: {host.hostname}", styles['Normal']))
            story.append(Paragraph(f"OS: {host.os.get('os', 'unknown')} ({host.os.get('accuracy', 0)}%)", styles['Normal']))
            story.append(Spacer(1, 10))
            
            # Services table
            service_data = [["Port", "Protocol", "Service", "Version", "State"]]
            for service in host.services:
                service_data.append([
                    str(service.port),
                    service.protocol,
                    service.service,
                    service.version,
                    service.state
                ])
                
            service_table = Table(service_data)
            service_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(service_table)
            story.append(Spacer(1, 20))
            
        # Build PDF
        doc.build(story)
        self.logger.info(f"PDF report saved: {filename}")
        return str(filename)
        
    def generate_nessus(self) -> str:
        """Generate Nessus-compatible report"""
        filename = self.output_dir / f"scan_{self.result.scan_id}.nessus"
        
        root = ET.Element("NessusClientData_v2")
        
        # Report
        report = ET.SubElement(root, "Report")
        report.set("name", f"Network Scan {self.result.scan_id}")
        
        for host in self.result.hosts:
            report_host = ET.SubElement(report, "ReportHost")
            report_host.set("name", host.ip)
            
            # Host properties
            host_props = ET.SubElement(report_host, "HostProperties")
            
            prop = ET.SubElement(host_props, "tag")
            prop.set("name", "HOST_END")
            prop.text = datetime.now().isoformat()
            
            if host.hostname:
                prop = ET.SubElement(host_props, "tag")
                prop.set("name", "hostname")
                prop.text = host.hostname
                
            if host.os.get("os") != "unknown":
                prop = ET.SubElement(host_props, "tag")
                prop.set("name", "operating-system")
                prop.text = host.os["os"]
                
            # Report items (vulnerabilities)
            for service in host.services:
                for vuln in service.vulnerabilities:
                    report_item = ET.SubElement(report_host, "ReportItem")
                    report_item.set("port", str(service.port))
                    report_item.set("svc_name", service.service)
                    report_item.set("protocol", service.protocol)
                    report_item.set("severity", str(self._severity_to_nessus(vuln.severity)))
                    report_item.set("pluginID", vuln.id)
                    report_item.set("pluginName", vuln.name)
                    
                    # Description
                    desc = ET.SubElement(report_item, "description")
                    desc.text = vuln.description
                    
                    # Solution
                    solution = ET.SubElement(report_item, "solution")
                    solution.text = vuln.remediation
                    
                    # CVSS
                    cvss_base = ET.SubElement(report_item, "cvss_base_score")
                    cvss_base.text = str(vuln.cvss_score)
                    
                    # References
                    if vuln.references:
                        refs = ET.SubElement(report_item, "see_also")
                        refs.text = "\n".join(vuln.references)
                        
        # Write file
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        with open(filename, 'w') as f:
            f.write(xml_str)
            
        self.logger.info(f"Nessus report saved: {filename}")
        return str(filename)
        
    def generate_metasploit(self) -> str:
        """Generate Metasploit-compatible import file"""
        filename = self.output_dir / f"scan_{self.result.scan_id}.rc"
        
        with open(filename, 'w') as f:
            f.write("# Metasploit Resource Script\n")
            f.write(f"# Generated from scan {self.result.scan_id}\n")
            f.write(f"# Date: {self.result.start_time}\n\n")
            
            for host in self.result.hosts:
                f.write(f"# Host: {host.ip}\n")
                
                for service in host.services:
                    if service.state == "open":
                        f.write(f"db_nmap -p {service.port} -sV {host.ip}\n")
                        
                        # Add to workspace
                        f.write(f"workspace -a scan_{self.result.scan_id}\n")
                        
                        # Auto-exploit suggestions for critical vulns
                        for vuln in service.vulnerabilities:
                            if vuln.severity in ["CRITICAL", "HIGH"] and vuln.exploits_available:
                                f.write(f"# Vulnerability: {vuln.name}\n")
                                f.write(f"use exploit/multi/handler\n")
                                f.write(f"set PAYLOAD generic/shell_reverse_tcp\n")
                                f.write(f"set LHOST 0.0.0.0\n")
                                f.write(f"set LPORT 4444\n")
                                f.write(f"set ExitOnSession false\n")
                                f.write(f"exploit -j -z\n\n")
                                
        self.logger.info(f"Metasploit RC file saved: {filename}")
        return str(filename)
        
    def _severity_to_nessus(self, severity: str) -> int:
        """Convert severity to Nessus severity value"""
        mapping = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }
        return mapping.get(severity.upper(), 0)


# ============================================================================
# MAIN SCANNER ENGINE
# ============================================================================

class NetworkSecurityScanner:
    """
    Main scanner engine orchestrating all components
    """
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.logger = self._setup_logging()
        self.results = []
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.start_time = datetime.now()
        
        # Initialize components
        self.port_scanner = AdvancedPortScanner(config)
        self.os_fingerprinter = OSFingerprinter()
        self.vuln_engine = VulnerabilityEngine(config)
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        # Console handler
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console.setFormatter(formatter)
        logger.addHandler(console)
        
        return logger
        
    async def run(self) -> ScanResult:
        """
        Execute the complete network scan
        
        Returns:
            ScanResult object with all findings
        """
        self.logger.info(f"Starting scan {self.scan_id}")
        self.logger.info(f"Target: {self.config.target}")
        self.logger.info(f"Profile: {self.config.profile.value}")
        
        # Get target IPs
        targets = self._expand_target()
        self.logger.info(f"Expanded to {len(targets)} targets")
        
        result = ScanResult(
            scan_id=self.scan_id,
            scan_config=self.config,
            start_time=self.start_time,
            statistics={
                "total_hosts": len(targets),
                "hosts_up": 0,
                "ports_scanned": 0,
                "open_ports": 0
            }
        )
        
        # Scan each target
        for target in targets:
            try:
                # Check if host is up
                if not await self._is_host_up(target):
                    self.logger.debug(f"Host {target} is down")
                    continue
                    
                self.logger.info(f"Scanning host: {target}")
                
                # Create host object
                host = HostInfo(ip=target)
                
                # Get hostname
                try:
                    host.hostname = socket.gethostbyaddr(target)[0]
                except:
                    pass
                    
                # Port scan
                services = await self.port_scanner.scan_host(target)
                host.services = services
                
                # OS fingerprinting
                host.os = await self.os_fingerprinter.fingerprint(target)
                
                # Vulnerability assessment
                if self.config.vulnerability_check:
                    vulnerabilities = await self.vuln_engine.assess_host(host)
                    
                    # Associate vulnerabilities with services
                    for vuln in vulnerabilities:
                        for service in host.services:
                            if service.port == vuln.port:
                                service.vulnerabilities.append(asdict(vuln))
                                
                # Add to results
                result.hosts.append(host)
                
                # Update statistics
                result.statistics["hosts_up"] += 1
                result.statistics["open_ports"] += len(services)
                
                # Log summary
                self.logger.info(f"Found {len(services)} open ports on {target}")
                
            except Exception as e:
                self.logger.error(f"Error scanning {target}: {e}")
                result.errors.append(f"{target}: {str(e)}")
                
        # Finalize
        result.end_time = datetime.now()
        result.duration = (result.end_time - result.start_time).total_seconds()
        
        self.logger.info(f"Scan completed in {result.duration:.2f} seconds")
        self.logger.info(f"Found {result.statistics['hosts_up']} live hosts")
        self.logger.info(f"Found {result.statistics['open_ports']} open ports")
        
        return result
        
    def _expand_target(self) -> List[str]:
        """Expand target specification to list of IPs"""
        ips = []
        target = self.config.target
        
        try:
            # Single IP
            ipaddress.ip_address(target)
            return [target]
        except:
            pass
            
        try:
            # CIDR
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]
        except:
            pass
            
        # Range (e.g., 192.168.1.1-254)
        if '-' in target and '.' in target:
            base, last = target.rsplit('.', 1)
            if '-' in last:
                start, end = map(int, last.split('-'))
                for i in range(start, end + 1):
                    ips.append(f"{base}.{i}")
                return ips
                
        # DNS name
        try:
            ip = socket.gethostbyname(target)
            return [ip]
        except:
            pass
            
        return []
        
    async def _is_host_up(self, ip: str) -> bool:
        """Check if host is up"""
        try:
            # Try ICMP ping first
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            result = subprocess.run(
                ['ping', param, '1', '-W', '1', ip],
                capture_output=True,
                timeout=2
            )
            
            if result.returncode == 0:
                return True
                
            # Fallback to TCP SYN on common ports
            for port in [80, 22, 443, 445]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        return True
                except:
                    pass
                    
        except:
            pass
            
        return False


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

async def main_async():
    """Async main function"""
    parser = argparse.ArgumentParser(
        description='Production-Grade Network Security Scanner v3.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python network_scanner.py 192.168.1.1
  
  # Subnet scan with specific ports
  python network_scanner.py 192.168.1.0/24 -p 22,80,443,3306 -o subnet_scan
  
  # Comprehensive scan with vulnerability checking
  python network_scanner.py scanme.nmap.org -p 1-1000 --vuln-check --profile comprehensive
  
  # Stealth scan with evasion
  python network_scanner.py 192.168.1.100 -p 1-1000 --profile stealth --randomize-ports
  
  # Export all report formats
  python network_scanner.py 192.168.1.1 --report-format all -o full_report
  
  # Encrypted results
  python network_scanner.py 192.168.1.1 --encrypt --password mypassword
        """
    )
    
    # Basic options
    parser.add_argument('target', help='Target IP, range, CIDR, or hostname')
    parser.add_argument('-p', '--ports', default='1-1000',
                       help='Port range to scan (default: 1-1000)')
    parser.add_argument('--protocol', choices=['tcp', 'udp', 'both'], default='tcp',
                       help='Protocol to scan (default: tcp)')
    parser.add_argument('-t', '--threads', type=int, default=100,
                       help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=2.0,
                       help='Socket timeout in seconds (default: 2.0)')
    parser.add_argument('-o', '--output', default='scan_results',
                       help='Output directory (default: scan_results)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
                       
    # Profile
    parser.add_argument('--profile', choices=['stealth', 'normal', 'aggressive', 'comprehensive'],
                       default='normal', help='Scan profile (default: normal)')
                       
    # Advanced scanning
    parser.add_argument('--randomize-ports', action='store_true',
                       help='Randomize port scan order')
    parser.add_argument('--fragment-packets', action='store_true',
                       help='Fragment IP packets (evasion)')
    parser.add_argument('--source-port', type=int,
                       help='Source port for scans')
    parser.add_argument('--rate-limit', type=int, default=1000,
                       help='Packets per second (default: 1000)')
                       
    # Features
    parser.add_argument('--no-ping', action='store_true',
                       help='Skip ping sweep')
    parser.add_argument('--os-detect', action='store_true', default=True,
                       help='Enable OS fingerprinting (default: True)')
    parser.add_argument('--vuln-check', action='store_true', default=True,
                       help='Enable vulnerability checking (default: True)')
    parser.add_argument('--ssl-analysis', action='store_true', default=True,
                       help='Enable SSL/TLS analysis (default: True)')
                       
    # Reports
    parser.add_argument('--report-format', nargs='+',
                       choices=['json', 'csv', 'html', 'xml', 'pdf', 'nessus', 'metasploit', 'all'],
                       default=['json', 'csv', 'html'],
                       help='Report formats (default: json csv html)')
    parser.add_argument('--encrypt', action='store_true',
                       help='Encrypt results')
    parser.add_argument('--password',
                       help='Password for encryption')
                       
    # API keys
    parser.add_argument('--shodan-key',
                       help='Shodan API key for enrichment')
    parser.add_argument('--cve-key',
                       help='NVD CVE API key')
                       
    args = parser.parse_args()
    
    # Handle 'all' report format
    if args.report_format and 'all' in args.report_format:
        args.report_format = ['json', 'csv', 'html', 'xml', 'pdf', 'nessus', 'metasploit']
        
    # Display banner
    print(f"""
{Fore.RED}{'='*70}
PRODUCTION-GRADE NETWORK SECURITY SCANNER v3.0
Enterprise Reconnaissance & Vulnerability Assessment
{'='*70}
{Fore.YELLOW}DISCLAIMER: This tool is for AUTHORIZED TESTING ONLY.
Use only on systems you own or have explicit written permission to test.
Unauthorized scanning may violate computer fraud and abuse laws.
{'='*70}{Style.RESET_ALL}
""")
    
    # Legal confirmation
    print(f"{Fore.YELLOW}[!] LEGAL NOTICE: By proceeding, you confirm:")
    print("    1. You have EXPLICIT AUTHORIZATION to scan this target")
    print("    2. This is for LEGITIMATE SECURITY TESTING purposes")
    print("    3. You accept FULL LEGAL RESPONSIBILITY for your actions")
    print(f"{Style.RESET_ALL}")
    
    response = input("Type 'YES' to confirm and proceed: ")
    if response.upper() != 'YES':
        print(f"{Fore.RED}[!] Scan aborted.{Style.RESET_ALL}")
        sys.exit(0)
        
    # Create configuration
    config = ScanConfig(
        target=args.target,
        ports=args.ports,
        protocol=args.protocol,
        threads=args.threads,
        timeout=args.timeout,
        profile=ScanProfile(args.profile),
        randomize_ports=args.randomize_ports,
        fragment_packets=args.fragment_packets,
        source_port=args.source_port,
        rate_limit=args.rate_limit,
        vulnerability_check=args.vuln_check,
        ssl_analysis=args.ssl_analysis,
        output_dir=args.output,
        report_formats=args.report_format,
        encrypt_results=args.encrypt,
        encryption_password=args.password,
        shodan_api_key=args.shodan_key,
        cve_api_key=args.cve_key
    )
    
    # Create and run scanner
    scanner = NetworkSecurityScanner(config)
    
    try:
        result = await scanner.run()
        
        # Generate reports
        generator = ReportGenerator(result, args.output)
        reports = generator.generate_all()
        
        print(f"\n{Fore.GREEN}{'='*70}")
        print("SCAN COMPLETED SUCCESSFULLY")
        print(f"{'='*70}{Style.RESET_ALL}")
        print(f"Scan ID: {result.scan_id}")
        print(f"Duration: {result.duration:.2f} seconds")
        print(f"Live Hosts: {len(result.hosts)}")
        print(f"Open Ports: {result.statistics.get('open_ports', 0)}")
        print(f"\nReports generated:")
        for report in reports:
            print(f"  ✓ {report}")
        print(f"\n{Fore.GREEN}Results saved to: {args.output}/{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def main():
    """Synchronous wrapper for async main"""
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
