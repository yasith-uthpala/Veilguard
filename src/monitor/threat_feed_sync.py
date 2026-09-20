"""
Veilguard — High-Speed Threat Feed Synchronizer

Downloads, parses, and indexes real-world threat feeds directly into SQLite:
  1. URLhaus (Abuse.ch): Active malware distribution domains and IP addresses
  2. ThreatFox (Abuse.ch): Active botnet C2 servers and indicators of compromise

Provides sub-millisecond local indexed lookups and auto-sync throttling.
"""

import sys
import time
import threading
import requests
import re
from typing import Dict, List, Tuple, Optional
from rich.console import Console

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console()

class ThreatFeedSync:
    """Synchronizes external threat intelligence into local SQLite database."""

    FEEDS = {
        "urlhaus": {
            "name": "URLhaus Malware Feed (Abuse.ch)",
            "url": "https://urlhaus.abuse.ch/downloads/text_online/",
            "threat_type": "malware",
            "threat_level": "critical",
            "format": "url_list",
        },
        "threatfox": {
            "name": "ThreatFox C2 & Botnets (Abuse.ch)",
            "url": "https://threatfox.abuse.ch/downloads/hostfile/",
            "threat_type": "c2",
            "threat_level": "critical",
            "format": "hosts",
        }
    }

    def __init__(self, db=None):
        if db is None:
            try:
                from src.db.database import Database
            except ImportError:
                from db.database import Database
            self.db = Database()
        else:
            self.db = db

        self._last_sync_time: float = 0
        self._sync_in_progress: bool = False
        self._lock = threading.Lock()

    @staticmethod
    def _extract_host(url_or_host: str) -> Optional[Tuple[str, str]]:
        """
        Extract clean hostname/IP and determine if it is an IP or domain.
        Returns: (clean_indicator, indicator_type) or None
        """
        s = url_or_host.strip().lower()
        if not s or s.startswith("#"):
            return None

        # Strip protocol
        for prefix in ("https://", "http://", "ftp://"):
            if s.startswith(prefix):
                s = s[len(prefix):]

        # Strip path, port, params
        s = s.split("/")[0].split("?")[0].split("#")[0].split(":")[0].rstrip(".")

        if not s or len(s) < 3 or " " in s:
            return None

        # Check if IP address (IPv4)
        ip_match = re.match(r"^(\d{1,3}\.){3}\d{1,3}$", s)
        if ip_match:
            # Skip loopback and private
            parts = s.split(".")
            if parts[0] in ("127", "0", "10", "192", "172", "169"):
                return None
            return s, "ip"

        # Basic domain validation
        if "." in s and not s.endswith(".local") and s not in ("localhost", "broadcasthost"):
            return s, "domain"

        return None

    def sync(self, force: bool = False, verbose: bool = True) -> Dict[str, int]:
        """
        Download feeds and batch insert indicators into SQLite database.
        Returns counts per feed.
        """
        with self._lock:
            now = time.time()
            # Throttle to max once per 4 hours unless force=True
            if not force and (now - self._last_sync_time) < (4 * 3600):
                if verbose:
                    console.print("[dim]Threat feeds are up to date (synced within last 4 hours).[/dim]")
                return {"status": "skipped", "reason": "recently_synced"}

            if self._sync_in_progress:
                return {"status": "in_progress"}

            self._sync_in_progress = True

        try:
            if verbose:
                console.print("\n[bold cyan]🔄 Synchronizing Real-World Threat Intelligence Feeds...[/bold cyan]")

            results = {}
            total_inserted = 0

            for feed_key, feed_meta in self.FEEDS.items():
                if verbose:
                    console.print(f"[dim]Downloading {feed_meta['name']}...[/dim]")

                try:
                    resp = requests.get(feed_meta["url"], timeout=15)
                    resp.raise_for_status()
                    lines = resp.text.splitlines()

                    threats_to_insert = []
                    feed_format = feed_meta["format"]
                    threat_type = feed_meta["threat_type"]
                    threat_level = feed_meta["threat_level"]

                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        extracted = None
                        if feed_format == "hosts":
                            parts = line.split()
                            if len(parts) >= 2 and parts[0] in ("127.0.0.1", "0.0.0.0"):
                                extracted = self._extract_host(parts[1])
                        else:  # url_list
                            extracted = self._extract_host(line)

                        if extracted:
                            indicator, ind_type = extracted
                            threats_to_insert.append({
                                "indicator": indicator,
                                "indicator_type": ind_type,
                                "threat_type": threat_type,
                                "threat_level": threat_level,
                                "source": feed_key,
                                "details": f"Active threat listed on {feed_meta['name']}"
                            })

                    count = self.db.bulk_insert_threats(threats_to_insert)
                    results[feed_key] = count
                    total_inserted += count
                    if verbose:
                        console.print(f"  [green]✔ {feed_meta['name']}: {count:,} indicators indexed[/green]")

                except Exception as e:
                    if verbose:
                        console.print(f"  [yellow]⚠ Warning: Failed to sync {feed_key}: {e}[/yellow]")
                    results[feed_key] = 0

            self._last_sync_time = time.time()
            if verbose:
                stats = self.db.get_threat_stats()
                console.print(f"[bold green]✅ Threat Intel Database Ready — {stats.get('total_indicators', 0):,} active indicators indexed![/bold green]\n")

            return {
                "status": "success",
                "total_indexed": total_inserted,
                "feeds": results
            }

        finally:
            with self._lock:
                self._sync_in_progress = False

    def start_background_sync(self, interval_hours: int = 6):
        """Run periodic feed updates in a background thread."""
        def sync_worker():
            # Initial sync on startup
            time.sleep(2)
            self.sync(verbose=False)
            while True:
                time.sleep(interval_hours * 3600)
                self.sync(force=True, verbose=False)

        threading.Thread(target=sync_worker, daemon=True).start()


# Module singleton
threat_feed_sync = ThreatFeedSync()
