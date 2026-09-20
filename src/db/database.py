import sqlite3
import os
import datetime
from rich.console import Console
from rich.table import Table

console = Console()

DB_PATH = os.path.join(os.path.dirname(__file__), "../../veilguard.db")


class Database:
    def __init__(self):
        self.path = os.path.abspath(DB_PATH)
        self.init()

    def connect(self):
        return sqlite3.connect(self.path)

    def init(self):
        with self.connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    target      TEXT,
                    ip          TEXT,
                    hostname    TEXT,
                    port        INTEGER,
                    proto       TEXT,
                    state       TEXT,
                    service     TEXT,
                    product     TEXT,
                    is_vulnerable INTEGER,
                    vuln_reason TEXT,
                    country     TEXT,
                    city        TEXT,
                    isp         TEXT,
                    is_high_risk INTEGER,
                    scanned_at  TEXT
                )
            """)
            
            # Add missing columns if they don't exist
            cursor = conn.execute("PRAGMA table_info(scans)")
            columns = {row[1] for row in cursor.fetchall()}
            
            new_columns = {
                'country': 'TEXT',
                'city': 'TEXT',
                'isp': 'TEXT',
                'is_high_risk': 'INTEGER'
            }
            
            for col_name, col_type in new_columns.items():
                if col_name not in columns:
                    conn.execute(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}")
                    console.print(f"[dim]Added column: {col_name}[/dim]")
            
            # Website monitoring tables
            conn.execute("""
                CREATE TABLE IF NOT EXISTS website_visits (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain          TEXT,
                    timestamp       TEXT,
                    ip_address      TEXT,
                    port            INTEGER,
                    pid             INTEGER,
                    process_name    TEXT,
                    is_https        INTEGER,
                    is_blocked      INTEGER,
                    threat_type     TEXT,
                    threat_level    TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blocked_sites (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain          TEXT UNIQUE,
                    threat_type     TEXT,
                    threat_level    TEXT,
                    reason          TEXT,
                    added_at        TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS website_alerts (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain          TEXT,
                    threat_type     TEXT,
                    threat_level    TEXT,
                    details         TEXT,
                    pid             INTEGER,
                    process_name    TEXT,
                    alert_time      TEXT
                )
            """)
            
            # Real-world Threat Intelligence Feeds table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator       TEXT UNIQUE,
                    indicator_type  TEXT,
                    threat_type     TEXT,
                    threat_level    TEXT,
                    source          TEXT,
                    details         TEXT,
                    added_at        TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_indicator ON threat_intelligence(indicator)")

            # Domain reputation cache (VirusTotal results)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS domain_reputation_cache (
                    domain          TEXT PRIMARY KEY,
                    verdict         TEXT,
                    verdict_label   TEXT,
                    malicious       INTEGER,
                    suspicious      INTEGER,
                    harmless        INTEGER,
                    undetected      INTEGER,
                    reputation      INTEGER,
                    total_engines   INTEGER,
                    cached_at       TEXT
                )
            """)

            conn.commit()
        console.print("[dim]Database ready.[/dim]")

    def save_scan(self, results: list):
        with self.connect() as conn:
            for r in results:
                conn.execute("""
                    INSERT INTO scans
                    (target, ip, hostname, port, proto, state, service,
                     product, is_vulnerable, vuln_reason, country, city, isp, 
                     is_high_risk, scanned_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    r["target"], r["ip"], r["hostname"], r["port"],
                    r["proto"], r["state"], r["service"], r["product"],
                    int(r["is_vulnerable"]), r["vuln_reason"],
                    r.get("country", "N/A"), r.get("city", "N/A"), 
                    r.get("isp", "N/A"), int(r.get("is_high_risk", 0)), 
                    r["scanned_at"]
                ))
            conn.commit()

    def show_history(self):
        with self.connect() as conn:
            rows = conn.execute("""
                SELECT target, ip, port, service, is_vulnerable, scanned_at
                FROM scans ORDER BY scanned_at DESC LIMIT 50
            """).fetchall()

        if not rows:
            console.print("[yellow]No scan history yet.[/yellow]")
            return

        table = Table(title="Scan History", border_style="purple")
        table.add_column("Target",      style="cyan")
        table.add_column("IP")
        table.add_column("Port",        style="cyan")
        table.add_column("Service")
        table.add_column("Vulnerable")
        table.add_column("Scanned at",  style="dim")

        for row in rows:
            vuln = "[red]YES[/red]" if row[4] else "[green]No[/green]"
            table.add_row(row[0], row[1], str(row[2]), row[3], vuln, row[5])

        console.print(table)

    def save_blocked_site(self, domain: str, threat_type: str = "malicious", threat_level: str = "critical", reason: str = ""):
        """Record or update a blocked site in the database."""
        now = datetime.datetime.now().isoformat()
        with self.connect() as conn:
            conn.execute("""
                INSERT INTO blocked_sites (domain, threat_type, threat_level, reason, added_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    threat_type = excluded.threat_type,
                    threat_level = excluded.threat_level,
                    reason = excluded.reason,
                    added_at = excluded.added_at
            """, (domain.lower(), threat_type, threat_level, reason, now))
            conn.commit()

    def remove_blocked_site(self, domain: str) -> bool:
        """Remove a site from the blocked_sites database table."""
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM blocked_sites WHERE domain = ?", (domain.lower(),))
            conn.commit()
            return cur.rowcount > 0

    def get_blocked_sites(self) -> list:
        """Retrieve all blocked sites from the database."""
        with self.connect() as conn:
            rows = conn.execute("""
                SELECT domain, threat_type, threat_level, reason, added_at
                FROM blocked_sites ORDER BY added_at DESC
            """).fetchall()
            return [
                {
                    "domain": r[0],
                    "threat_type": r[1],
                    "threat_level": r[2],
                    "reason": r[3],
                    "added_at": r[4]
                }
                for r in rows
            ]

    def clear_all_blocked_sites(self):
        """Clear all entries from the blocked_sites table."""
        with self.connect() as conn:
            conn.execute("DELETE FROM blocked_sites")
            conn.commit()

    def bulk_insert_threats(self, threats: list) -> int:
        """
        Batch insert threats into threat_intelligence table using executemany.
        threats: list of dicts with keys (indicator, indicator_type, threat_type, threat_level, source, details)
        """
        if not threats:
            return 0
        now = datetime.datetime.now().isoformat()
        records = [
            (
                t["indicator"].lower(),
                t.get("indicator_type", "domain"),
                t.get("threat_type", "malware"),
                t.get("threat_level", "critical"),
                t.get("source", "feed"),
                t.get("details", ""),
                now
            )
            for t in threats
        ]
        with self.connect() as conn:
            cur = conn.executemany("""
                INSERT INTO threat_intelligence (indicator, indicator_type, threat_type, threat_level, source, details, added_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(indicator) DO UPDATE SET
                    threat_type = excluded.threat_type,
                    threat_level = excluded.threat_level,
                    source = excluded.source,
                    details = excluded.details
            """, records)
            conn.commit()
            return cur.rowcount

    def lookup_threat(self, indicator: str) -> dict:
        """Sub-millisecond indexed lookup for a domain or IP in threat_intelligence table."""
        clean = indicator.strip().lower().removeprefix("www.")
        with self.connect() as conn:
            row = conn.execute("""
                SELECT indicator, indicator_type, threat_type, threat_level, source, details, added_at
                FROM threat_intelligence WHERE indicator = ? OR indicator = ?
                LIMIT 1
            """, (clean, f"www.{clean}")).fetchone()
            if row:
                return {
                    "indicator": row[0],
                    "indicator_type": row[1],
                    "threat_type": row[2],
                    "threat_level": row[3],
                    "source": row[4],
                    "details": row[5],
                    "added_at": row[6]
                }
        return None

    def save_domain_cache(self, domain: str, data: dict):
        """Cache VirusTotal domain result in SQLite."""
        now = datetime.datetime.now().isoformat()
        clean = domain.strip().lower()
        with self.connect() as conn:
            conn.execute("""
                INSERT INTO domain_reputation_cache 
                (domain, verdict, verdict_label, malicious, suspicious, harmless, undetected, reputation, total_engines, cached_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    verdict = excluded.verdict,
                    verdict_label = excluded.verdict_label,
                    malicious = excluded.malicious,
                    suspicious = excluded.suspicious,
                    harmless = excluded.harmless,
                    undetected = excluded.undetected,
                    reputation = excluded.reputation,
                    total_engines = excluded.total_engines,
                    cached_at = excluded.cached_at
            """, (
                clean,
                data.get("verdict", "clean"),
                data.get("verdict_label", "Clean"),
                data.get("malicious", 0),
                data.get("suspicious", 0),
                data.get("harmless", 0),
                data.get("undetected", 0),
                data.get("reputation", 0),
                data.get("total_engines", 0),
                now
            ))
            conn.commit()

    def get_domain_cache(self, domain: str) -> dict:
        """Retrieve cached VirusTotal domain reputation."""
        clean = domain.strip().lower()
        with self.connect() as conn:
            row = conn.execute("""
                SELECT domain, verdict, verdict_label, malicious, suspicious, harmless, undetected, reputation, total_engines, cached_at
                FROM domain_reputation_cache WHERE domain = ?
            """, (clean,)).fetchone()
            if row:
                return {
                    "domain": row[0],
                    "verdict": row[1],
                    "verdict_label": row[2],
                    "malicious": row[3],
                    "suspicious": row[4],
                    "harmless": row[5],
                    "undetected": row[6],
                    "reputation": row[7],
                    "total_engines": row[8],
                    "cached_at": row[9]
                }
        return None

    def get_threat_stats(self) -> dict:
        """Return total counts of threat indicators in database."""
        with self.connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM threat_intelligence").fetchone()[0]
            by_type = dict(conn.execute("""
                SELECT threat_type, COUNT(*) FROM threat_intelligence GROUP BY threat_type
            """).fetchall())
            by_source = dict(conn.execute("""
                SELECT source, COUNT(*) FROM threat_intelligence GROUP BY source
            """).fetchall())
            cache_count = conn.execute("SELECT COUNT(*) FROM domain_reputation_cache").fetchone()[0]
            return {
                "total_indicators": total,
                "by_type": by_type,
                "by_source": by_source,
                "cached_domains": cache_count
            }