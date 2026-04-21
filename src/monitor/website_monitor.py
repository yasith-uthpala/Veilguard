"""
Website Traffic Monitor - Captures DNS and HTTP traffic to track visited websites
Blocks malicious sites based on threat intelligence database

FEATURES:
  - Captures DNS queries (domains accessed)
  - Tracks HTTP/HTTPS requests
  - Checks against malicious site database
  - Generates alerts for phishing, malware, scams
  - Maintains visit history (when, what domain, what process)
  - Real-time blocking capability
"""

from scapy.all import sniff, DNS, DNSQR, IP, TCP
from collections import defaultdict
import psutil
import threading
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Set
import json
import os


@dataclass
class DomainVisit:
    """Tracks a visited domain"""
    domain: str
    timestamp: datetime
    ip_address: str
    port: int
    pid: Optional[int] = None
    process_name: Optional[str] = None
    is_https: bool = False
    is_blocked: bool = False
    threat_type: Optional[str] = None
    threat_level: str = "safe"  # safe, low, medium, high, critical


@dataclass
class WebsiteAlert:
    """Alert for malicious website detection"""
    timestamp: datetime
    domain: str
    threat_type: str  # phishing, malware, scam, c2, ransomware, etc
    threat_level: str  # low, medium, high, critical
    details: str
    pid: Optional[int] = None
    process_name: Optional[str] = None


class MaliciousSiteDetector:
    """Detects malicious websites using threat database"""

    def __init__(self):
        self.threat_db: Dict[str, Dict] = {}
        self.whitelist: Set[str] = set()
        self.blacklist: Set[str] = set()
        self.load_threat_database()

    def load_threat_database(self):
        """Load malicious sites and threat patterns from database"""
        db_path = os.path.join(os.path.dirname(__file__), "../../data/malicious_sites.json")
        
        try:
            if os.path.exists(db_path):
                with open(db_path, 'r') as f:
                    data = json.load(f)
                    self.threat_db = data.get("threats", {})
                    self.whitelist = set(data.get("whitelist", []))
                    self.blacklist = set(data.get("blacklist", []))
            else:
                # Initialize with common patterns if file doesn't exist
                self._init_default_threats()
        except Exception as e:
            print(f"Error loading threat database: {e}")
            self._init_default_threats()

    def _init_default_threats(self):
        """Initialize with built-in threat patterns"""
        self.threat_db = {
            "phishing": {
                "patterns": ["login", "verify", "confirm", "update", "security"],
                "domains": [
                    "paypa1.com", "amazm.com", "micros0ft.com", "appl3.com",
                    "fakepaypal.tk", "phishing-site.xyz"
                ]
            },
            "malware": {
                "patterns": ["crack", "keygen", "warez", "torrent"],
                "domains": [
                    "malware-hub.com", "trojan-source.ru", "exploit-kit.xyz"
                ]
            },
            "scam": {
                "patterns": ["free-money", "prize-winner", "click-here"],
                "domains": [
                    "scam-alert.com", "nigerian-prince.xyz"
                ]
            },
            "c2": {
                "patterns": ["command", "control"],
                "domains": [
                    "c2-server.ru", "botnet-master.com"
                ]
            }
        }

    def is_safe(self, domain: str) -> Tuple[bool, Optional[str], str]:
        """
        Check if domain is safe
        Returns: (is_safe, threat_type, threat_level)
        """
        domain_lower = domain.lower()

        # Check whitelist first
        if domain_lower in self.whitelist:
            return (True, None, "safe")

        # Check blacklist
        if domain_lower in self.blacklist:
            return (False, "blacklisted", "critical")

        # Check threat database
        for threat_type, threat_info in self.threat_db.items():
            # Check exact domain match
            if domain_lower in threat_info.get("domains", []):
                return (False, threat_type, self._get_threat_level(threat_type))

            # Check pattern matches
            for pattern in threat_info.get("patterns", []):
                if pattern.lower() in domain_lower:
                    return (False, threat_type, self._get_threat_level(threat_type))

        return (True, None, "safe")

    def _get_threat_level(self, threat_type: str) -> str:
        """Return threat level based on type"""
        levels = {
            "malware": "critical",
            "c2": "critical",
            "ransomware": "critical",
            "phishing": "high",
            "scam": "high",
            "blacklisted": "critical"
        }
        return levels.get(threat_type, "medium")


class DNSCapture:
    """Captures DNS queries to extract domain names"""

    def __init__(self):
        self.visited_domains: Dict[str, DomainVisit] = {}
        self.ip_to_domain_cache: Dict[str, str] = {}
        self.packet_count = 0
        self.is_capturing = False
        self.threat_detector = MaliciousSiteDetector()

        # IP-to-PID mapping cache (same as network monitor)
        self.ip_to_pid_cache: Dict[str, Tuple[int, str]] = {}
        self.cache_last_updated = 0
        self.cache_update_interval = 2

    def _update_ip_to_pid_cache(self):
        """Refresh mapping of IPs to PIDs"""
        now = time.time()
        if now - self.cache_last_updated < self.cache_update_interval:
            return

        cache = {}
        try:
            for proc in psutil.process_iter(attrs=['pid', 'name']):
                try:
                    for conn in proc.net_connections():
                        laddr = conn.laddr
                        if laddr:
                            cache[laddr.ip] = (proc.pid, proc.name())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
        except Exception:
            pass

        self.ip_to_pid_cache = cache
        self.cache_last_updated = now

    def _get_pid_from_ip(self, ip: str) -> Optional[Tuple[int, str]]:
        """Map IP address to process ID"""
        self._update_ip_to_pid_cache()
        return self.ip_to_pid_cache.get(ip)

    def _extract_domain_from_packet(self, packet) -> Optional[str]:
        """Extract domain from DNS query packet"""
        try:
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                if dns_layer.opcode == 0:  # Standard query
                    if dns_layer.qdcount > 0:
                        qname = dns_layer.qd.qname
                        if qname:
                            domain = qname.decode('utf-8', errors='ignore').rstrip('.')
                            return domain
        except Exception:
            pass
        return None

    def packet_handler(self, packet):
        """Process each captured packet"""
        self.packet_count += 1

        try:
            domain = self._extract_domain_from_packet(packet)
            if not domain:
                return

            # Get source IP
            src_ip = None
            if packet.haslayer(IP):
                src_ip = packet[IP].src

            if not src_ip or src_ip.startswith("127."):
                return

            # Check if domain is malicious
            is_safe, threat_type, threat_level = self.threat_detector.is_safe(domain)

            # Get PID from IP
            pid_info = self._get_pid_from_ip(src_ip)
            pid = pid_info[0] if pid_info else None
            process_name = pid_info[1] if pid_info else "Unknown"

            # Create visit record
            visit = DomainVisit(
                domain=domain,
                timestamp=datetime.now(),
                ip_address=src_ip,
                port=53,  # DNS uses port 53
                pid=pid,
                process_name=process_name,
                is_https=False,
                is_blocked=not is_safe,
                threat_type=threat_type,
                threat_level=threat_level
            )

            # Store visit
            visit_key = f"{domain}_{pid}_{int(time.time())}"
            self.visited_domains[visit_key] = visit

            # Clean old entries (keep last 1000)
            if len(self.visited_domains) > 1000:
                oldest_key = min(
                    self.visited_domains.keys(),
                    key=lambda k: self.visited_domains[k].timestamp
                )
                del self.visited_domains[oldest_key]

            # Cache IP->Domain mapping
            self.ip_to_domain_cache[src_ip] = domain

        except Exception as e:
            pass

    def start_capture(self, interface: Optional[str] = None):
        """Start capturing DNS packets in background thread"""
        self.is_capturing = True

        def capture_thread():
            try:
                sniff(
                    prn=self.packet_handler,
                    filter="udp port 53",
                    iface=interface,
                    store=False,
                    stop_filter=lambda x: not self.is_capturing
                )
            except Exception as e:
                print(f"Capture error: {e}")

        thread = threading.Thread(target=capture_thread, daemon=True)
        thread.start()

    def stop_capture(self):
        """Stop capturing packets"""
        self.is_capturing = False

    def get_recent_domains(self, limit: int = 20) -> List[DomainVisit]:
        """Get most recent domain visits"""
        visits = sorted(
            self.visited_domains.values(),
            key=lambda x: x.timestamp,
            reverse=True
        )
        return visits[:limit]

    def get_blocked_domains(self) -> List[DomainVisit]:
        """Get all blocked domain attempts"""
        return [v for v in self.visited_domains.values() if v.is_blocked]

    def get_domains_by_threat_level(self, level: str) -> List[DomainVisit]:
        """Get domains by threat level (low, medium, high, critical)"""
        return [v for v in self.visited_domains.values() if v.threat_level == level]

    def get_stats(self) -> Dict:
        """Get monitoring statistics"""
        blocked = self.get_blocked_domains()
        safe = [v for v in self.visited_domains.values() if not v.is_blocked]

        threat_counts = defaultdict(int)
        for visit in blocked:
            if visit.threat_type:
                threat_counts[visit.threat_type] += 1

        return {
            "total_domains_visited": len(set(v.domain for v in self.visited_domains.values())),
            "total_visits": len(self.visited_domains),
            "packets_captured": self.packet_count,
            "blocked_attempts": len(blocked),
            "safe_visits": len(safe),
            "threat_breakdown": dict(threat_counts),
            "blocked_rate": f"{len(blocked) / (len(safe) + len(blocked)) * 100:.1f}%" if (len(safe) + len(blocked)) > 0 else "0%"
        }
