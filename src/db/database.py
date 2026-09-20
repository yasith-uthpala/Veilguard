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

            # File hash reputation cache (VirusTotal results for binaries)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_hash_cache (
                    sha256           TEXT PRIMARY KEY,
                    verdict          TEXT,
                    verdict_label    TEXT,
                    malicious_count  INTEGER,
                    suspicious_count INTEGER,
                    total_engines    INTEGER,
                    threat_label     TEXT,
                    meaningful_name  TEXT,
                    cached_at        TEXT
                )
            """)

            # Multi-Agent Correlated Security Incidents
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_incidents (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT,
                    severity        TEXT,
                    risk_score      INTEGER,
                    event_type      TEXT,
                    process_name    TEXT,
                    pid             INTEGER,
                    exe_path        TEXT,
                    sha256          TEXT,
                    remote_ip       TEXT,
                    remote_port     INTEGER,
                    domain          TEXT,
                    summary         TEXT,
                    details_json    TEXT,
                    action_taken    TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_time ON security_incidents(timestamp)")

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
            hash_count = conn.execute("SELECT COUNT(*) FROM file_hash_cache").fetchone()[0]
            incident_count = conn.execute("SELECT COUNT(*) FROM security_incidents").fetchone()[0]
            return {
                "total_indicators": total,
                "by_type": by_type,
                "by_source": by_source,
                "cached_domains": cache_count,
                "cached_file_hashes": hash_count,
                "total_incidents": incident_count,
            }

    # ---------------------------------------------------------------------------
    # File Hash Reputation Cache
    # ---------------------------------------------------------------------------

    def save_file_hash_cache(self, sha256: str, data: dict):
        """Save VirusTotal / reputation scan result for a binary file hash."""
        now = datetime.datetime.now().isoformat()
        clean_hash = sha256.strip().lower()
        with self.connect() as conn:
            conn.execute("""
                INSERT INTO file_hash_cache
                (sha256, verdict, verdict_label, malicious_count, suspicious_count, total_engines, threat_label, meaningful_name, cached_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    verdict = excluded.verdict,
                    verdict_label = excluded.verdict_label,
                    malicious_count = excluded.malicious_count,
                    suspicious_count = excluded.suspicious_count,
                    total_engines = excluded.total_engines,
                    threat_label = excluded.threat_label,
                    meaningful_name = excluded.meaningful_name,
                    cached_at = excluded.cached_at
            """, (
                clean_hash,
                data.get("verdict", "unknown"),
                data.get("verdict_label", "Unknown"),
                data.get("malicious", 0),
                data.get("suspicious", 0),
                data.get("total_engines", 0),
                data.get("threat_label", ""),
                data.get("meaningful_name", ""),
                now
            ))
            conn.commit()

    def get_file_hash_cache(self, sha256: str) -> Optional[dict]:
        """Fetch cached reputation for a file hash."""
        clean_hash = sha256.strip().lower()
        with self.connect() as conn:
            row = conn.execute("""
                SELECT sha256, verdict, verdict_label, malicious_count, suspicious_count, total_engines, threat_label, meaningful_name, cached_at
                FROM file_hash_cache WHERE sha256 = ?
            """, (clean_hash,)).fetchone()
            if row:
                return {
                    "sha256": row[0],
                    "verdict": row[1],
                    "verdict_label": row[2],
                    "malicious": row[3],
                    "suspicious": row[4],
                    "total_engines": row[5],
                    "threat_label": row[6],
                    "meaningful_name": row[7],
                    "cached_at": row[8],
                }
        return None

    # ---------------------------------------------------------------------------
    # Multi-Agent Correlated Incidents
    # ---------------------------------------------------------------------------

    def save_incident(self, incident: dict) -> int:
        """Save a multi-agent security incident to the database. Returns incident ID."""
        import json
        now = datetime.datetime.now().isoformat()
        with self.connect() as conn:
            cur = conn.execute("""
                INSERT INTO security_incidents
                (timestamp, severity, risk_score, event_type, process_name, pid, exe_path, sha256, remote_ip, remote_port, domain, summary, details_json, action_taken)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident.get("timestamp", now),
                incident.get("severity", "MEDIUM"),
                incident.get("risk_score", 50),
                incident.get("event_type", "ANOMALY"),
                incident.get("process_name", "Unknown"),
                incident.get("pid"),
                incident.get("exe_path", ""),
                incident.get("sha256", ""),
                incident.get("remote_ip", ""),
                incident.get("remote_port"),
                incident.get("domain", ""),
                incident.get("summary", ""),
                json.dumps(incident.get("details", {}), default=str),
                incident.get("action_taken", "ALERT_ONLY")
            ))
            conn.commit()
            return cur.lastrowid

    def get_incidents(self, limit: int = 50, min_severity: Optional[str] = None) -> list:
        """Retrieve recent security incidents."""
        import json
        query = "SELECT id, timestamp, severity, risk_score, event_type, process_name, pid, exe_path, sha256, remote_ip, remote_port, domain, summary, details_json, action_taken FROM security_incidents"
        params = []
        if min_severity:
            query += " WHERE severity = ?"
            params.append(min_severity)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self.connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            results = []
            for r in rows:
                try:
                    details = json.loads(r[13]) if r[13] else {}
                except Exception:
                    details = {}
                results.append({
                    "id": r[0],
                    "timestamp": r[1],
                    "severity": r[2],
                    "risk_score": r[3],
                    "event_type": r[4],
                    "process_name": r[5],
                    "pid": r[6],
                    "exe_path": r[7],
                    "sha256": r[8],
                    "remote_ip": r[9],
                    "remote_port": r[10],
                    "domain": r[11],
                    "summary": r[12],
                    "details": details,
                    "action_taken": r[14],
                })
            return results

    def clear_incidents(self):
        """Clear all security incidents."""
        with self.connect() as conn:
            conn.execute("DELETE FROM security_incidents")
            conn.commit()

    # ---------------------------------------------------------------------------
    # Website Visits & Alerts Persistence
    # ---------------------------------------------------------------------------

    def save_website_visit(self, domain: str, ip_address: str, port: int = 53,
                           pid: Optional[int] = None, process_name: Optional[str] = None,
                           is_https: bool = False, is_blocked: bool = False,
                           threat_type: Optional[str] = None, threat_level: str = "safe"):
        """Save a visited domain query into the database."""
        now = datetime.datetime.now().isoformat()
        with self.connect() as conn:
            conn.execute("""
                INSERT INTO website_visits
                (domain, timestamp, ip_address, port, pid, process_name, is_https, is_blocked, threat_type, threat_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                domain.lower(), now, ip_address, port, pid, process_name or "Unknown",
                1 if is_https else 0, 1 if is_blocked else 0, threat_type, threat_level
            ))
            conn.commit()

    def get_website_visits(self, limit: int = 50) -> list:
        """Fetch recent website visits."""
        with self.connect() as conn:
            rows = conn.execute("""
                SELECT domain, timestamp, ip_address, port, pid, process_name, is_https, is_blocked, threat_type, threat_level
                FROM website_visits ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
            return [
                {
                    "domain": r[0],
                    "timestamp": r[1],
                    "ip_address": r[2],
                    "port": r[3],
                    "pid": r[4],
                    "process_name": r[5],
                    "is_https": bool(r[6]),
                    "is_blocked": bool(r[7]),
                    "threat_type": r[8],
                    "threat_level": r[9],
                }
                for r in rows
            ]

    def save_website_alert(self, domain: str, threat_type: str, threat_level: str,
                           details: str, pid: Optional[int] = None, process_name: Optional[str] = None):
        """Save an alert generated by website monitoring."""
        now = datetime.datetime.now().isoformat()
        with self.connect() as conn:
            conn.execute("""
                INSERT INTO website_alerts
                (domain, threat_type, threat_level, details, pid, process_name, alert_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (domain.lower(), threat_type, threat_level, details, pid, process_name or "Unknown", now))
            conn.commit()

    def get_website_alerts(self, limit: int = 50) -> list:
        """Fetch recent website alerts."""
        with self.connect() as conn:
            rows = conn.execute("""
                SELECT domain, threat_type, threat_level, details, pid, process_name, alert_time
                FROM website_alerts ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
            return [
                {
                    "domain": r[0],
                    "threat_type": r[1],
                    "threat_level": r[2],
                    "details": r[3],
                    "pid": r[4],
                    "process_name": r[5],
                    "alert_time": r[6],
                }
                for r in rows
            ]