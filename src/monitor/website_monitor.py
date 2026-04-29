"""
Website Traffic Monitor - Captures DNS and HTTP traffic to track visited websites
Blocks malicious sites based on threat intelligence database

FEATURES:
  - Captures DNS queries (domains accessed)
  - Tracks HTTP/HTTPS requests
  - Checks against malicious site database (URLhaus, PhishTank, Spamhaus)
  - Generates alerts for phishing, malware, scams
  - Maintains visit history (when, what domain, what process)
  - Real-time blocking capability
  - Auto-refreshes threat feeds every 6 hours
"""

from scapy.all import sniff, DNS, DNSQR, IP, TCP
from collections import defaultdict
import psutil
import threading
import time
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional, Set
import json
import os
import uuid
import urllib.request
import csv
import io


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
    threat_level: str = "safe"


@dataclass
class WebsiteAlert:
    """Alert for malicious website detection"""
    timestamp: datetime
    domain: str
    threat_type: str
    threat_level: str
    details: str
    pid: Optional[int] = None
    process_name: Optional[str] = None


class ThreatFeedLoader:
    """
    Loads real threat intelligence from external feeds.
    Sources:
      - URLhaus  (abuse.ch) : active malware domains
      - PhishTank           : confirmed phishing sites
      - Spamhaus DBL        : spam/malware domains
      - Pi-hole blocklist   : broad ad/malware domain list
    """

    FEEDS = {
        "urlhaus": {
            "url": "https://urlhaus.abuse.ch/downloads/text_online/",
            "threat_type": "malware",
            "threat_level": "critical",
            "parser": "plain_domains",
        },
        "phishtank": {
            "url": "http://data.phishtank.com/data/online-valid.csv",
            "threat_type": "phishing",
            "threat_level": "high",
            "parser": "phishtank_csv",
        },
        "spamhaus_dbl": {
            "url": "https://www.spamhaus.org/drop/dbl.txt",
            "threat_type": "spam",
            "threat_level": "high",
            "parser": "plain_domains",
        },
        "pihole": {
            "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "threat_type": "malware",
            "threat_level": "medium",
            "parser": "hosts_file",
        },
    }

    def __init__(self):
        # domain -> (threat_type, threat_level)
        self.feed_domains: Dict[str, Tuple[str, str]] = {}
        self._lock = threading.Lock()

    def _parse_plain_domains(self, content: str, threat_type: str, threat_level: str):
        """Parse plain line-by-line domain/URL list (URLhaus, Spamhaus)"""
        count = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # URLhaus gives full URLs — extract hostname
            domain = self._extract_domain(line)
            if domain:
                self.feed_domains[domain] = (threat_type, threat_level)
                count += 1
        return count

    def _parse_phishtank_csv(self, content: str, threat_type: str, threat_level: str):
        """Parse PhishTank CSV — columns: phish_id, url, phish_detail_url, ..."""
        count = 0
        try:
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                url = row.get("url", "")
                domain = self._extract_domain(url)
                if domain:
                    self.feed_domains[domain] = (threat_type, threat_level)
                    count += 1
        except Exception:
            pass
        return count

    def _parse_hosts_file(self, content: str, threat_type: str, threat_level: str):
        """Parse HOSTS file format (Pi-hole): '0.0.0.0 domain.com'"""
        count = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            # Hosts file format: <ip> <domain>
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                domain = parts[1].lower()
                if domain and domain not in ("localhost", "broadcasthost"):
                    self.feed_domains[domain] = (threat_type, threat_level)
                    count += 1
        return count

    def _extract_domain(self, url_or_domain: str) -> Optional[str]:
        """Extract clean domain from URL or raw domain string"""
        try:
            s = url_or_domain.strip().lower()
            # Remove protocol
            for prefix in ("https://", "http://", "ftp://"):
                if s.startswith(prefix):
                    s = s[len(prefix):]
            # Remove path, port, query
            s = s.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
            # Basic validation
            if "." in s and len(s) > 3 and " " not in s:
                return s
        except Exception:
            pass
        return None

    def load_feed(self, name: str, feed: dict) -> int:
        """Download and parse a single feed. Returns count of domains loaded."""
        try:
            req = urllib.request.Request(
                feed["url"],
                headers={"User-Agent": "Mozilla/5.0 (threat-monitor/1.0)"}
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                content = response.read().decode("utf-8", errors="ignore")

            parser = feed["parser"]
            threat_type = feed["threat_type"]
            threat_level = feed["threat_level"]

            if parser == "plain_domains":
                return self._parse_plain_domains(content, threat_type, threat_level)
            elif parser == "phishtank_csv":
                return self._parse_phishtank_csv(content, threat_type, threat_level)
            elif parser == "hosts_file":
                return self._parse_hosts_file(content, threat_type, threat_level)

        except Exception as e:
            print(f"  [ThreatFeed] Failed to load '{name}': {e}")
        return 0

    def load_all(self):
        """Load all feeds. Safe to call from a background thread."""
        print("[ThreatFeed] Loading threat intelligence feeds...")
        total = 0
        new_domains: Dict[str, Tuple[str, str]] = {}

        for name, feed in self.FEEDS.items():
            count = self.load_feed(name, feed)
            print(f"  [ThreatFeed] {name}: {count} domains loaded")
            total += count

        with self._lock:
            self.feed_domains.update(new_domains)

        print(f"[ThreatFeed] Total: {total} threat domains loaded\n")

    def check(self, domain: str) -> Tuple[bool, Optional[str], str]:
        """
        Check domain against loaded feeds.
        Returns: (is_malicious, threat_type, threat_level)
        """
        with self._lock:
            result = self.feed_domains.get(domain.lower())

        if result:
            return (True, result[0], result[1])
        return (False, None, "safe")

    def start_auto_refresh(self, interval_hours: int = 6):
        """Auto-refresh feeds every N hours in background"""
        def refresh_loop():
            while True:
                time.sleep(interval_hours * 3600)
                print("[ThreatFeed] Refreshing threat feeds...")
                self.load_all()

        thread = threading.Thread(target=refresh_loop, daemon=True)
        thread.start()


class MaliciousSiteDetector:
    """
    Detects malicious websites using:
      1. Local whitelist / trusted domains (fast path)
      2. Local blacklist (fast path)
      3. Real-time threat feeds (URLhaus, PhishTank, Spamhaus, Pi-hole)
      4. Hardcoded fallback patterns (offline fallback)
    """

    TRUSTED_DOMAINS = {
        "google.com", "microsoft.com", "apple.com", "amazon.com",
        "github.com", "cloudflare.com", "facebook.com", "twitter.com",
        "linkedin.com", "youtube.com", "reddit.com", "wikipedia.org",
        "accounts.google.com", "login.microsoftonline.com",
        "icloud.com", "live.com", "office.com", "googleapis.com",
        "gstatic.com", "akamai.com", "fastly.net", "amazonaws.com",
    }

    def __init__(self):
        self.threat_db: Dict[str, Dict] = {}
        self.whitelist: Set[str] = set()
        self.blacklist: Set[str] = set()
        self.feed_loader = ThreatFeedLoader()
        self.load_threat_database()

        # Load live feeds immediately, then auto-refresh every 6 hours
        feed_thread = threading.Thread(
            target=self.feed_loader.load_all, daemon=True
        )
        feed_thread.start()
        self.feed_loader.start_auto_refresh(interval_hours=6)

    def load_threat_database(self):
        """Load local threat database from JSON file"""
        db_path = os.path.join(
            os.path.dirname(__file__), "../../data/malicious_sites.json"
        )
        try:
            if os.path.exists(db_path):
                with open(db_path, "r") as f:
                    data = json.load(f)
                    self.threat_db = data.get("threats", {})
                    self.whitelist = set(data.get("whitelist", []))
                    self.blacklist = set(data.get("blacklist", []))
            else:
                self._init_default_threats()
        except Exception as e:
            print(f"Error loading threat database: {e}")
            self._init_default_threats()

    def _init_default_threats(self):
        """Offline fallback — minimal hardcoded patterns"""
        self.threat_db = {
            "phishing": {
                "patterns": ["paypa1", "amazn", "micros0ft", "appl3", "g00gle"],
                "domains": [
                    "paypa1.com", "amazm.com", "micros0ft.com",
                    "fakepaypal.tk", "phishing-site.xyz"
                ],
            },
            "malware": {
                "patterns": ["malware-hub", "trojan-source", "exploit-kit"],
                "domains": [
                    "malware-hub.com", "trojan-source.ru", "exploit-kit.xyz"
                ],
            },
            "scam": {
                "patterns": ["free-money", "prize-winner", "nigerian-prince"],
                "domains": ["scam-alert.com", "nigerian-prince.xyz"],
            },
            "c2": {
                "patterns": ["c2-server", "botnet-master"],
                "domains": ["c2-server.ru", "botnet-master.com"],
            },
        }

    def _is_trusted(self, domain: str) -> bool:
        """Check if domain or any parent is in the trusted set"""
        if domain in self.TRUSTED_DOMAINS:
            return True
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            if ".".join(parts[i:]) in self.TRUSTED_DOMAINS:
                return True
        return False

    def is_safe(self, domain: str) -> Tuple[bool, Optional[str], str]:
        """
        Full threat check pipeline.
        Returns: (is_safe, threat_type, threat_level)
        """
        domain_lower = domain.lower()

        # 1. Trusted / whitelisted — skip all checks
        if domain_lower in self.whitelist or self._is_trusted(domain_lower):
            return (True, None, "safe")

        # 2. Local explicit blacklist
        if domain_lower in self.blacklist:
            return (False, "blacklisted", "critical")

        # 3. Live threat feeds (URLhaus, PhishTank, Spamhaus, Pi-hole)
        is_malicious, threat_type, threat_level = self.feed_loader.check(domain_lower)
        if is_malicious:
            return (False, threat_type, threat_level)

        # 4. Local threat DB — exact domain match
        for t_type, t_info in self.threat_db.items():
            if domain_lower in [d.lower() for d in t_info.get("domains", [])]:
                return (False, t_type, self._get_threat_level(t_type))

        # 5. Local threat DB — pattern match (offline fallback only)
        for t_type, t_info in self.threat_db.items():
            for pattern in t_info.get("patterns", []):
                if pattern.lower() in domain_lower:
                    return (False, t_type, self._get_threat_level(t_type))

        return (True, None, "safe")

    def _get_threat_level(self, threat_type: str) -> str:
        levels = {
            "malware": "critical",
            "c2": "critical",
            "ransomware": "critical",
            "phishing": "high",
            "scam": "high",
            "spam": "medium",
            "blacklisted": "critical",
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
        self._lock = threading.Lock()

        self._port_pid_cache: Dict[int, Tuple[int, str]] = {}
        self._cache_last_updated: float = 0
        self._cache_update_interval: float = 2.0

    def _update_port_pid_cache(self):
        """Refresh mapping of local UDP ports to PIDs"""
        now = time.time()
        if now - self._cache_last_updated < self._cache_update_interval:
            return

        cache: Dict[int, Tuple[int, str]] = {}
        try:
            for proc in psutil.process_iter(attrs=["pid", "name"]):
                try:
                    for conn in proc.net_connections(kind="udp"):
                        if conn.laddr:
                            cache[conn.laddr.port] = (
                                proc.info["pid"], proc.info["name"]
                            )
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
        except Exception:
            pass

        self._port_pid_cache = cache
        self._cache_last_updated = now

    def _get_process_from_port(self, port: int) -> Optional[Tuple[int, str]]:
        """Map a local UDP source port to (pid, process_name)"""
        self._update_port_pid_cache()
        return self._port_pid_cache.get(port)

    def _extract_domain_from_packet(self, packet) -> Optional[str]:
        """Extract domain name from DNS query packet"""
        try:
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                if dns_layer.opcode == 0 and dns_layer.qdcount > 0:
                    qname = dns_layer.qd.qname
                    if qname:
                        return qname.decode("utf-8", errors="ignore").rstrip(".")
        except Exception:
            pass
        return None

    def packet_handler(self, packet):
        """Process each captured packet"""
        self.packet_count += 1

        try:
            domain = self._extract_domain_from_packet(packet)
            if not domain or not packet.haslayer(IP):
                return

            src_ip = packet[IP].src
            src_port = getattr(packet, "sport", None)

            if src_ip.startswith("127."):
                return

            is_safe, threat_type, threat_level = self.threat_detector.is_safe(domain)

            pid, process_name = None, "Unknown"
            if src_port:
                proc_info = self._get_process_from_port(src_port)
                if proc_info:
                    pid, process_name = proc_info

            visit = DomainVisit(
                domain=domain,
                timestamp=datetime.now(),
                ip_address=src_ip,
                port=53,
                pid=pid,
                process_name=process_name,
                is_https=False,
                is_blocked=not is_safe,
                threat_type=threat_type,
                threat_level=threat_level,
            )

            visit_key = f"{domain}_{pid}_{uuid.uuid4().hex[:8]}"

            with self._lock:
                self.visited_domains[visit_key] = visit
                if len(self.visited_domains) > 1000:
                    oldest = min(
                        self.visited_domains,
                        key=lambda k: self.visited_domains[k].timestamp
                    )
                    del self.visited_domains[oldest]

            self.ip_to_domain_cache[src_ip] = domain

        except Exception:
            pass

    def start_capture(self, interface: Optional[str] = None):
        """Start capturing DNS packets (UDP + TCP port 53) in background"""
        self.is_capturing = True

        def capture_thread():
            try:
                sniff(
                    prn=self.packet_handler,
                    filter="port 53",
                    iface=interface,
                    store=False,
                    stop_filter=lambda x: not self.is_capturing,
                )
            except Exception as e:
                print(f"Capture error: {e}")

        threading.Thread(target=capture_thread, daemon=True).start()

    def stop_capture(self):
        self.is_capturing = False

    def get_recent_domains(self, limit: int = 20) -> List[DomainVisit]:
        with self._lock:
            visits = sorted(
                self.visited_domains.values(),
                key=lambda x: x.timestamp,
                reverse=True,
            )
        return visits[:limit]

    def get_blocked_domains(self, limit: Optional[int] = None) -> List[DomainVisit]:
        with self._lock:
            blocked = sorted(
                [v for v in self.visited_domains.values() if v.is_blocked],
                key=lambda x: x.timestamp,
                reverse=True,
            )
        return blocked[:limit] if limit else blocked

    def get_domains_by_threat_level(self, level: str) -> List[DomainVisit]:
        with self._lock:
            return [
                v for v in self.visited_domains.values()
                if v.threat_level == level
            ]

    def get_stats(self) -> Dict:
        with self._lock:
            all_visits = list(self.visited_domains.values())

        blocked = [v for v in all_visits if v.is_blocked]
        safe = [v for v in all_visits if not v.is_blocked]
        total = len(blocked) + len(safe)

        threat_counts: Dict[str, int] = defaultdict(int)
        for v in blocked:
            if v.threat_type:
                threat_counts[v.threat_type] += 1

        return {
            "total_domains_visited": len(set(v.domain for v in all_visits)),
            "total_visits": len(all_visits),
            "packets_captured": self.packet_count,
            "blocked_attempts": len(blocked),
            "safe_visits": len(safe),
            "threat_breakdown": dict(threat_counts),
            "blocked_rate": (
                f"{len(blocked) / total * 100:.1f}%" if total > 0 else "0%"
            ),
            "feed_domains_loaded": len(
                self.threat_detector.feed_loader.feed_domains
            ),
        }