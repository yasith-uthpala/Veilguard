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