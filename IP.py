#!/usr/bin/env python3
"""
Advanced Security Scanner Pro v3.0
A professional security scanner with capabilities:
- Multi-threaded port scanning
- Advanced IP geolocation
- Automatic service and version detection
- CVE vulnerability checking
- Professional reporting
- Enhanced user interface

⚠️ For educational purposes and authorized penetration testing only
"""

import socket
import requests
import re
import json
import threading
import time
import os
import sys
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Any
import argparse
from math import radians, sin, cos, sqrt, atan2

# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class GeolocationInfo:
    """Store geolocation information"""
    ip: str
    country: str
    country_code: str
    region: str
    city: str
    zip_code: str
    latitude: float
    longitude: float
    timezone: str
    isp: str
    org: str
    as_number: str
    query_time: str
    
    def __str__(self):
        return f"""
{'='*70}
🌍 Geolocation Information - {self.ip}
{'='*70}
📍 Location:
  • Country: {self.country} ({self.country_code})
  • Region: {self.region}
  • City: {self.city}
  • ZIP Code: {self.zip_code}

🎯 Coordinates:
  • Latitude: {self.latitude:.6f}
  • Longitude: {self.longitude:.6f}
  • Timezone: {self.timezone}

🖥️ Network Information:
  • ISP: {self.isp}
  • Organization: {self.org}
  • AS Number: {self.as_number}

⏰ Query Time: {self.query_time}
{'='*70}
"""

@dataclass
class PortInfo:
    """Store port information"""
    port: int
    state: str  # OPEN, CLOSED, FILTERED
    service: str
    version: str
    banner: str
    cve_list: List[str]
    scan_time: str
    
    def to_dict(self):
        return {
            'port': self.port,
            'state': self.state,
            'service': self.service,
            'version': self.version,
            'banner': self.banner[:100] if self.banner else '',
            'cve_count': len(self.cve_list),
            'cves': self.cve_list,
            'scan_time': self.scan_time
        }

@dataclass
class ScanResult:
    """Store complete scan results"""
    target: str
    start_time: str
    end_time: str
    duration: float
    total_ports_scanned: int
    open_ports: List[PortInfo]
    geolocation: Optional[GeolocationInfo]
    distances: Dict[str, float]
    
    def summary(self):
        return f"""
📊 Scan Summary:
{'='*70}
🎯 Target: {self.target}
⏰ Start Time: {self.start_time}
⏰ End Time: {self.end_time}
⏱️ Duration: {self.duration:.2f} seconds
🔍 Ports Scanned: {self.total_ports_scanned}
🚪 Open Ports: {len(self.open_ports)}

🌍 Location:
  • Country: {self.geolocation.country if self.geolocation else 'Unknown'}
  • City: {self.geolocation.city if self.geolocation else 'Unknown'}
  • ISP: {self.geolocation.isp if self.geolocation else 'Unknown'}

⚠️ Open Ports: {[p.port for p in self.open_ports]}
{'='*70}
"""

# ============================================================================
# Core Scanner Classes
# ============================================================================

class GeoLocator:
    """Manage IP geolocation"""
    
    APIS = {
        'ipapi': 'https://ipapi.co/{ip}/json/',
        'ipapi_com': 'http://ip-api.com/json/{ip}',
        'ipwhois': 'http://ipwho.is/{ip}',
        'ipinfo': 'https://ipinfo.io/{ip}/json'
    }
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityScanner/3.0',
            'Accept': 'application/json'
        })
    
    def locate(self, ip: str) -> Optional[GeolocationInfo]:
        """Get geolocation information"""
        for api_name, api_url in self.APIS.items():
            try:
                print(f"[+] Getting location from {api_name}...")
                response = self.session.get(api_url.format(ip=ip), timeout=5)
                response.raise_for_status()
                data = response.json()
                
                info = self._parse_response(data, api_name)
                if info:
                    print(f"[✓] Geolocation successful")
                    return info
                    
            except Exception as e:
                print(f"[-] Error with {api_name}: {str(e)[:50]}")
                continue
        
        return None
    
    def _parse_response(self, data: Dict, api_name: str) -> Optional[GeolocationInfo]:
        """Parse API response"""
        try:
            if api_name == 'ipapi':
                return GeolocationInfo(
                    ip=data.get('ip', ''),
                    country=data.get('country_name', 'Unknown'),
                    country_code=data.get('country_code', 'XX'),
                    region=data.get('region', 'Unknown'),
                    city=data.get('city', 'Unknown'),
                    zip_code=data.get('postal', 'Unknown'),
                    latitude=float(data.get('latitude', 0)),
                    longitude=float(data.get('longitude', 0)),
                    timezone=data.get('timezone', 'Unknown'),
                    isp=data.get('org', 'Unknown'),
                    org=data.get('org', 'Unknown'),
                    as_number=data.get('asn', 'Unknown'),
                    query_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
            elif api_name == 'ipapi_com':
                if data.get('status') == 'success':
                    return GeolocationInfo(
                        ip=data.get('query', ''),
                        country=data.get('country', 'Unknown'),
                        country_code=data.get('countryCode', 'XX'),
                        region=data.get('regionName', 'Unknown'),
                        city=data.get('city', 'Unknown'),
                        zip_code=data.get('zip', 'Unknown'),
                        latitude=float(data.get('lat', 0)),
                        longitude=float(data.get('lon', 0)),
                        timezone=data.get('timezone', 'Unknown'),
                        isp=data.get('isp', 'Unknown'),
                        org=data.get('org', 'Unknown'),
                        as_number=data.get('as', 'Unknown'),
                        query_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    )
        except Exception as e:
            print(f"[-] Error parsing response: {e}")
        
        return None
    
    def calculate_distances(self, lat: float, lon: float) -> Dict[str, float]:
        """Calculate distances to major cities"""
        cities = {
            'Tehran, Iran': (35.6892, 51.3890),
            'Mashhad, Iran': (36.2605, 59.6168),
            'Isfahan, Iran': (32.6546, 51.6680),
            'Shiraz, Iran': (29.5926, 52.5836),
            'Tabriz, Iran': (38.0962, 46.2738),
            'Kabul, Afghanistan': (34.5553, 69.2075),
            'Dushanbe, Tajikistan': (38.5598, 68.7870),
            'Dubai, UAE': (25.2048, 55.2708),
            'Ankara, Turkey': (39.9334, 32.8597),
            'Istanbul, Turkey': (41.0082, 28.9784),
            'London, UK': (51.5074, -0.1278),
            'New York, USA': (40.7128, -74.0060),
            'Tokyo, Japan': (35.6762, 139.6503),
            'Singapore': (1.3521, 103.8198)
        }
        
        distances = {}
        for city, (city_lat, city_lon) in cities.items():
            distances[city] = self._haversine_distance(lat, lon, city_lat, city_lon)
        
        return distances
    
    @staticmethod
    def _haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance using Haversine formula"""
        R = 6371  # Earth radius in kilometers
        
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        return round(R * c, 1)


class ServiceDetector:
    """Detect service and version"""
    
    SERVICE_PATTERNS = {
        r'Server:\s*(.*?)(?:\r\n|$)': 'HTTP Server',
        r'SSH-\d\.\d-(.*)': 'SSH',
        r'FTP server\s*\(?(.*?)\)?': 'FTP',
        r'^220\s+(.*?)\s+ESMTP': 'SMTP',
        r'Microsoft.*?IIS/(\d+\.\d+)': 'IIS',
        r'nginx/(\d+\.\d+\.\d+)': 'nginx',
        r'Apache/(\d+\.\d+\.\d+)': 'Apache',
        r'OpenSSH_(\d+\.\d+)': 'OpenSSH',
        r'ProFTPD (\d+\.\d+\.\d+)': 'ProFTPD',
        r'MySQL.*?(\d+\.\d+\.\d+)': 'MySQL',
        r'PostgreSQL (\d+\.\d+)': 'PostgreSQL',
        r'Redis.*?v=(\d+\.\d+)': 'Redis',
        r'MongoDB.*?(\d+\.\d+\.\d+)': 'MongoDB',
        r'Tomcat/(\d+\.\d+\.\d+)': 'Tomcat',
    }
    
    COMMON_PORTS = {
        21: ('FTP', ''),
        22: ('SSH', ''),
        23: ('Telnet', ''),
        25: ('SMTP', ''),
        53: ('DNS', ''),
        80: ('HTTP', ''),
        110: ('POP3', ''),
        143: ('IMAP', ''),
        443: ('HTTPS', ''),
        465: ('SMTPS', ''),
        587: ('SMTP', ''),
        993: ('IMAPS', ''),
        995: ('POP3S', ''),
        1433: ('MSSQL', ''),
        1521: ('Oracle DB', ''),
        3306: ('MySQL', ''),
        3389: ('RDP', ''),
        5432: ('PostgreSQL', ''),
        5900: ('VNC', ''),
        6379: ('Redis', ''),
        8000: ('HTTP Alt', ''),
        8080: ('HTTP Proxy', ''),
        8443: ('HTTPS Alt', ''),
        8888: ('HTTP Alt', ''),
        27017: ('MongoDB', ''),
        28017: ('MongoDB HTTP', ''),
    }
    
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
    
    def probe_service(self, target: str, port: int) -> Tuple[str, str, str]:
        """Probe service to get information"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((target, port))
                
                # Try to get banner
                banner = ""
                try:
                    if port == 80:
                        sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
                
                service, version = self._analyze_banner(banner, port)
                return service, version, banner
                
        except:
            service, version = self.COMMON_PORTS.get(port, ("Unknown", ""))
            return service, version, ""
            
    def _analyze_banner(self, banner: str, port: int) -> Tuple[str, str]:
        """Analyze banner to detect service and version"""
        if not banner:
            return self.COMMON_PORTS.get(port, ("Unknown", ""))
            
        for pattern, service_name in self.SERVICE_PATTERNS.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else ""
                return service_name, version
                
        return self.COMMON_PORTS.get(port, ("Unknown", ""))


class CVEChecker:
    """Check for known vulnerabilities"""
    
    def __init__(self):
        self.session = requests.Session()
    
    def check_vulnerabilities(self, service: str, version: str) -> List[str]:
        """Check for CVEs (Simulated for this script)"""
        if not service or service == "Unknown" or not version:
            return []
            
        # In a real scenario, this would query a CVE database API
        # For this professional script, we simulate detection based on version
        vulnerabilities = []
        
        # Example simulation logic
        if "Apache" in service and "2.4.49" in version:
            vulnerabilities.append("CVE-2021-41773 (Path Traversal)")
        elif "OpenSSH" in service and "8.2" in version:
            vulnerabilities.append("CVE-2020-15778 (scp command injection)")
            
        return vulnerabilities


class PortScanner:
    """Main port scanner engine"""
    
    def __init__(self, target: str, max_threads: int = 50):
        self.target = target
        self.max_threads = max_threads
        self.detector = ServiceDetector()
        self.cve_checker = CVEChecker()
        self.print_lock = threading.Lock()
        
    def scan_port(self, port: int) -> Optional[PortInfo]:
        """Scan a single port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.5)
                result = sock.connect_ex((self.target, port))
                
                if result == 0:
                    # Port is open, probe for service
                    service, version, banner = self.detector.probe_service(self.target, port)
                    cves = self.cve_checker.check_vulnerabilities(service, version)
                    
                    return PortInfo(
                        port=port,
                        state="OPEN",
                        service=service,
                        version=version,
                        banner=banner,
                        cve_list=cves,
                        scan_time=datetime.now().strftime("%H:%M:%S")
                    )
        except:
            pass
        return None

    def scan_range(self, start_port: int, end_port: int) -> List[PortInfo]:
        """Scan a range of ports using thread pool"""
        open_ports = []
        total_ports = end_port - start_port + 1
        scanned = 0
        
        print(f"[*] Scanning {total_ports} ports with {self.max_threads} threads...")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all ports to thread pool
            future_to_port = {
                executor.submit(self.scan_port, port): port 
                for port in range(start_port, end_port + 1)
            }
            
            # Process results
            for future in as_completed(future_to_port):
                scanned += 1
                port = future_to_port[future]
                
                # Show progress
                if scanned % 100 == 0 or scanned == total_ports:
                    progress = (scanned / total_ports) * 100
                    print(f"[{progress:6.2f}%] Scanned: {scanned}/{total_ports}", end='\r')
                
                try:
                    result = future.result()
                    if result and result.state == "OPEN":
                        open_ports.append(result)
                        # Quick display of open port
                        print(f"\n[+] Port {result.port}: {result.service} {result.version}")
                        
                except Exception as e:
                    print(f"\n[-] Error on port {port}: {e}")
        
        print(f"\n[✓] Scan complete. Found {len(open_ports)} open ports.")
        return open_ports


# ============================================================================
# User Interface and Reporting
# ============================================================================

class ScannerUI:
    """Scanner user interface"""
    
    @staticmethod
    def show_banner():
        """Show program banner"""
        banner = """
╔══════════════════════════════════════════════════════════╗
║     🚀 Advanced Security Scanner Pro v3.0                ║
║     📍 Geolocation + Port Scan + CVE Detection          ║
║     ⚠️  For Educational & Authorized Testing Only        ║
╚══════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    @staticmethod
    def get_target():
        """Get target from user"""
        print("\n🎯 Scan Settings:")
        print("-" * 50)
        
        target = input("IP Address or Hostname (e.g., 192.168.1.1 or google.com): ").strip()
        
        # Convert hostname to IP
        if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target):
            try:
                target = socket.gethostbyname(target)
                print(f"[✓] Resolved to IP: {target}")
            except socket.gaierror:
                print("[✗] Error: Invalid hostname!")
                return None
        
        return target
    
    @staticmethod
    def get_port_range():
        """Get port range from user"""
        try:
            print("\n🔢 Port Range:")
            print("   (Defaults: 1-1000)")
            
            start = input("   Start Port [1]: ").strip()
            end = input("   End Port [1000]: ").strip()
            
            start_port = int(start) if start else 1
            end_port = int(end) if end else 1000
            
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                print("[✗] Error: Invalid port range!")
                return None, None
            
            return start_port, end_port
            
        except ValueError:
            print("[✗] Error: Please enter numbers only!")
            return None, None
    
    @staticmethod
    def get_thread_count():
        """Get thread count from user"""
        try:
            threads = input("\n🧵 Thread Count (default: 50): ").strip()
            return int(threads) if threads else 50
        except ValueError:
            return 50
    
    @staticmethod
    def display_results(scan_result: ScanResult, detailed: bool = True):
        """Display scan results"""
        print("\n" + "="*70)
        print("📋 Complete Scan Results")
        print("="*70)
        
        # Show summary
        print(scan_result.summary())
        
        # Show geolocation information
        if scan_result.geolocation:
            print(scan_result.geolocation)
            
            # Show distances to cities
            if scan_result.distances:
                print("📏 Distance to Major Cities:")
                for city, dist in sorted(scan_result.distances.items(), key=lambda x: x[1]):
                    print(f"  • {city}: {dist} km")
                print()
        
        # Show open ports with details
        if detailed and scan_result.open_ports:
            print("\n🚪 Open Ports with Details:")
            print("-" * 100)
            print(f"{'Port':<8} {'Service':<20} {'Version':<20} {'CVEs':<30} {'Time':<10}")
            print("-" * 100)
            
            for port_info in sorted(scan_result.open_ports, key=lambda x: x.port):
                cves_str = ", ".join(port_info.cve_list[:3])
                if len(port_info.cve_list) > 3:
                    cves_str += f" (+{len(port_info.cve_list)-3})"
                
                print(f"{port_info.port:<8} {port_info.service[:18]:<20} "
                      f"{port_info.version[:18]:<20} {cves_str[:28]:<30} {port_info.scan_time:<10}")
            
            print("-" * 100)
            
            # Show map links
            if scan_result.geolocation and scan_result.geolocation.latitude != 0:
                print("\n🗺️  Map Links:")
                lat = scan_result.geolocation.latitude
                lon = scan_result.geolocation.longitude
                print(f"  • Google Maps: https://www.google.com/maps?q={lat},{lon}")
                print(f"  • OpenStreetMap: https://www.openstreetmap.org/?mlat={lat}&mlon={lon}")


class ReportGenerator:
    """Generate reports in different formats"""
    
    @staticmethod
    def save_text_report(scan_result: ScanResult, filename: str = None):
        """Save text report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{scan_result.target}_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write("Security Scan Report\n")
            f.write("="*70 + "\n\n")
            
            # Target information
            f.write("🎯 Target Information:\n")
            f.write(f"  • Address: {scan_result.target}\n")
            f.write(f"  • Start Time: {scan_result.start_time}\n")
            f.write(f"  • End Time: {scan_result.end_time}\n")
            f.write(f"  • Duration: {scan_result.duration:.2f} seconds\n\n")
            
            # Geolocation information
            if scan_result.geolocation:
                f.write("🌍 Geolocation Information:\n")
                geo_dict = asdict(scan_result.geolocation)
                for key, value in geo_dict.items():
                    f.write(f"  • {key}: {value}\n")
                f.write("\n")
            
            # Open ports
            f.write(f"🚪 Open Ports ({len(scan_result.open_ports)} found):\n")
            for port_info in sorted(scan_result.open_ports, key=lambda x: x.port):
                f.write(f"\n  Port {port_info.port}:\n")
                f.write(f"    • Service: {port_info.service}\n")
                f.write(f"    • Version: {port_info.version}\n")
                f.write(f"    • State: {port_info.state}\n")
                f.write(f"    • CVEs: {', '.join(port_info.cve_list) if port_info.cve_list else 'None'}\n")
                if port_info.banner:
                    f.write(f"    • Banner: {port_info.banner[:100]}...\n")
            
            f.write("\n" + "="*70 + "\n")
        
        return filename
    
    @staticmethod
    def save_json_report(scan_result: ScanResult, filename: str = None):
        """Save JSON report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{scan_result.target}_{timestamp}.json"
        
        report = {
            'target': scan_result.target,
            'start_time': scan_result.start_time,
            'end_time': scan_result.end_time,
            'duration': scan_result.duration,
            'total_ports_scanned': scan_result.total_ports_scanned,
            'open_ports_count': len(scan_result.open_ports),
            'geolocation': asdict(scan_result.geolocation) if scan_result.geolocation else None,
            'distances': scan_result.distances,
            'open_ports': [p.to_dict() for p in scan_result.open_ports],
            'scan_metadata': {
                'version': '3.0',
                'tool': 'Advanced Security Scanner Pro',
                'generated_at': datetime.now().isoformat()
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filename
    
    @staticmethod
    def save_html_report(scan_result: ScanResult, filename: str = None):
        """Save HTML report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{scan_result.target}_{timestamp}.html"
        
        # Simple HTML template
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {scan_result.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #555; border-bottom: 2px solid #eee; padding-bottom: 5px; }}
        .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; }}
        .port-open {{ color: green; font-weight: bold; }}
        .port-closed {{ color: red; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
    </style>
</head>
<body>
    <h1>🔒 Security Scan Report</h1>
    
    <div class="summary">
        <h2>📊 Scan Summary</h2>
        <p><strong>Target:</strong> {scan_result.target}</p>
        <p><strong>Scan Time:</strong> {scan_result.start_time} to {scan_result.end_time}</p>
        <p><strong>Duration:</strong> {scan_result.duration:.2f} seconds</p>
    </div>
    
    <h2>🌍 Geolocation Information</h2>
    <p><strong>IP Address:</strong> {scan_result.geolocation.ip if scan_result.geolocation else 'N/A'}</p>
    <p><strong>Location:</strong> {scan_result.geolocation.city if scan_result.geolocation else 'N/A'}, 
       {scan_result.geolocation.country if scan_result.geolocation else 'N/A'}</p>
    <p><strong>ISP:</strong> {scan_result.geolocation.isp if scan_result.geolocation else 'N/A'}</p>
    
    <h2>🚪 Open Ports</h2>
    <table>
        <thead>
            <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Version</th>
                <th>CVEs</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {"".join([
                f'<tr><td>{p.port}</td><td>{p.service}</td><td>{p.version}</td>'
                f'<td>{", ".join(p.cve_list) if p.cve_list else "None"}</td>'
                f'<td class="port-open">OPEN</td></tr>'
                for p in scan_result.open_ports
            ])}
        </tbody>
    </table>
    
    <p><em>Report generated by Advanced Security Scanner Pro v3.0</em></p>
</body>
</html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        return filename


# ============================================================================
# Main Function
# ============================================================================

def main():
    """Main scanner execution function"""
    
    # Show banner
    ScannerUI.show_banner()
    
    # Get user input
    target = ScannerUI.get_target()
    if not target:
        return
    
    start_port, end_port = ScannerUI.get_port_range()
    if start_port is None:
        return
    
    thread_count = ScannerUI.get_thread_count()
    
    print("\n" + "="*70)
    print("[*] Starting scan process...")
    
    # Start time
    start_time = time.time()
    scan_start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. Get geolocation information
    print("[1/4] Getting geolocation information...")
    geolocator = GeoLocator()
    geo_info = geolocator.locate(target)
    distances = {}
    
    if geo_info:
        distances = geolocator.calculate_distances(geo_info.latitude, geo_info.longitude)
        print("[✓] Geolocation successful")
    else:
        print("[✗] Geolocation failed")
    
    # 2. Scan ports
    print(f"[2/4] Scanning ports {start_port}-{end_port}...")
    scanner = PortScanner(target, max_threads=thread_count)
    open_ports = scanner.scan_range(start_port, end_port)
    
    # 3. End time
    end_time = time.time()
    scan_end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duration = end_time - start_time
    
    # 4. Prepare results
    print("[3/4] Preparing results...")
    scan_result = ScanResult(
        target=target,
        start_time=scan_start_time,
        end_time=scan_end_time,
        duration=duration,
        total_ports_scanned=end_port - start_port + 1,
        open_ports=open_ports,
        geolocation=geo_info,
        distances=distances
    )
    
    # 5. Display results
    print("[4/4] Displaying results...")
    ScannerUI.display_results(scan_result)
    
    # 6. Save report
    print("\n💾 Save Report:")
    print("  1. Text Report")
    print("  2. JSON Report")
    print("  3. HTML Report")
    print("  4. All Formats")
    print("  5. Exit without saving")
    
    choice = input("\nYour choice [1-5]: ").strip()
    
    saved_files = []
    
    if choice in ['1', '4']:
        txt_file = ReportGenerator.save_text_report(scan_result)
        saved_files.append(f"Text: {txt_file}")
    
    if choice in ['2', '4']:
        json_file = ReportGenerator.save_json_report(scan_result)
        saved_files.append(f"JSON: {json_file}")
    
    if choice in ['3', '4']:
        html_file = ReportGenerator.save_html_report(scan_result)
        saved_files.append(f"HTML: {html_file}")
    
    if choice == '5':
        print("[*] Exiting without saving report")
    elif saved_files:
        print("\n[✓] Reports saved successfully:")
        for file in saved_files:
            print(f"  • {file}")
    
    print("\n" + "="*70)
    print("🎉 Scan completed! Press Enter to exit...")
    input()


# ============================================================================
# CLI Support
# ============================================================================

def cli_mode():
    """Command Line Interface mode"""
    parser = argparse.ArgumentParser(description='Advanced Security Scanner Pro v3.0')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-s', '--start-port', type=int, default=1, help='Start port (default: 1)')
    parser.add_argument('-e', '--end-port', type=int, default=1000, help='End port (default: 1000)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Thread count (default: 50)')
    parser.add_argument('-o', '--output', choices=['text', 'json', 'html', 'all'], 
                       default='text', help='Output format')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (minimal output)')
    
    args = parser.parse_args()
    
    if not args.quiet:
        ScannerUI.show_banner()
    
    print(f"[*] Starting scan on {args.target}")
    
    # Start time
    start_time = time.time()
    
    # Get geolocation
    geolocator = GeoLocator()
    geo_info = geolocator.locate(args.target)
    
    # Scan ports
    scanner = PortScanner(args.target, max_threads=args.threads)
    open_ports = scanner.scan_range(args.start_port, args.end_port)
    
    # End time
    end_time = time.time()
    duration = end_time - start_time
    
    # Prepare results
    scan_result = ScanResult(
        target=args.target,
        start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        end_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        duration=duration,
        total_ports_scanned=args.end_port - args.start_port + 1,
        open_ports=open_ports,
        geolocation=geo_info,
        distances={}
    )
    
    # Display results
    if not args.quiet:
        ScannerUI.display_results(scan_result, detailed=True)
    
    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f"scan_report_{args.target}_{timestamp}"
    
    if args.output in ['text', 'all']:
        ReportGenerator.save_text_report(scan_result, f"{base_filename}.txt")
    if args.output in ['json', 'all']:
        ReportGenerator.save_json_report(scan_result, f"{base_filename}.json")
    if args.output in ['html', 'all']:
        ReportGenerator.save_html_report(scan_result, f"{base_filename}.html")
    
    print(f"\n[✓] Scan completed in {duration:.2f} seconds")


# ============================================================================
# Program Execution
# ============================================================================

if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            # CLI mode
            cli_mode()
        else:
            # Interactive mode
            main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n✨ Program terminated.")
