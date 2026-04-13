import nmap
import socket
import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.columns import Columns
from rich import box
from .threat_lookup import ThreatLookup, CVELookup

console = Console()

VULNERABLE_PORTS = {
    21: {
        "name": "FTP",
        "risk": "HIGH",
        "opened_by": "FTP server software (FileZilla Server, IIS FTP)",
        "why_open": "Used to transfer files between computers over a network",
        "attacks": [
            "Anonymous login — attacker logs in with no credentials",
            "Brute force — password guessing attacks",
            "FTP Bounce — use your server to attack others",
            "Sniffing — credentials sent in plaintext, easily intercepted",
        ],
        "if_closed": "FTP file transfers will stop working",
        "recommendation": "CLOSE — use SFTP (port 22) instead, it is encrypted",
    },
    22: {
        "name": "SSH",
        "risk": "MEDIUM",
        "opened_by": "OpenSSH server or similar",
        "why_open": "Secure remote terminal access to the machine",
        "attacks": [
            "Brute force — password guessing (use key-based auth to prevent)",
            "Outdated SSH versions have known CVEs",
        ],
        "if_closed": "Remote terminal access will stop working",
        "recommendation": "KEEP — but disable password login, use SSH keys only",
    },
    23: {
        "name": "Telnet",
        "risk": "CRITICAL",
        "opened_by": "Telnet server service",
        "why_open": "Legacy remote access protocol (replaced by SSH)",
        "attacks": [
            "Full plaintext — everything including passwords visible on network",
            "Man-in-the-middle — attacker reads and modifies your session",
            "Credential theft — trivial to capture login details",
        ],
        "if_closed": "Telnet remote access stops — use SSH instead",
        "recommendation": "CLOSE IMMEDIATELY — completely insecure, use SSH",
    },
    25: {
        "name": "SMTP",
        "risk": "HIGH",
        "opened_by": "Mail server (Postfix, Exchange, Sendmail)",
        "why_open": "Sending and receiving email",
        "attacks": [
            "Open relay — your server used to send spam worldwide",
            "Email spoofing — send fake emails from your domain",
            "User enumeration — discover valid email accounts",
        ],
        "if_closed": "Email sending/receiving stops",
        "recommendation": "RESTRICT — only allow trusted mail servers",
    },
    80: {
        "name": "HTTP",
        "risk": "MEDIUM",
        "opened_by": "Web server (Apache, Nginx, IIS)",
        "why_open": "Serving unencrypted web pages",
        "attacks": [
            "Man-in-the-middle — traffic readable by anyone on network",
            "Cookie theft — session cookies intercepted",
            "Web app attacks — SQLi, XSS if app is vulnerable",
        ],
        "if_closed": "HTTP websites stop loading (HTTPS on 443 still works)",
        "recommendation": "REDIRECT to HTTPS (443) — do not serve content over HTTP",
    },
    135: {
        "name": "RPC / DCOM",
        "risk": "HIGH",
        "opened_by": "svchost.exe (Windows Service Host)",
        "why_open": "Windows Component Object Model (COM) service communication",
        "attacks": [
            "MS03-026 — used by Blaster worm to infect millions of PCs",
            "DCOM exploits — remote code execution via malformed RPC packets",
            "Lateral movement — attackers pivot through networks using RPC",
            "WMI abuse — attackers use WMI over RPC for persistence",
        ],
        "if_closed": "Windows printing, remote management may break",
        "recommendation": "BLOCK externally via Windows Firewall — keep localhost only",
    },
    139: {
        "name": "NetBIOS",
        "risk": "HIGH",
        "opened_by": "System (Windows kernel, PID 4)",
        "why_open": "Legacy Windows file and printer sharing",
        "attacks": [
            "NetBIOS name poisoning — LLMNR/NBT-NS attacks",
            "Credential capture — Responder tool captures NTLMv2 hashes",
            "SMB relay — captured hashes replayed to authenticate elsewhere",
        ],
        "if_closed": "Legacy Windows network browsing stops",
        "recommendation": "CLOSE if possible — disable NetBIOS over TCP/IP",
    },
    443: {
        "name": "HTTPS",
        "risk": "LOW",
        "opened_by": "Web server (Apache, Nginx, IIS)",
        "why_open": "Serving encrypted web pages",
        "attacks": [
            "SSL/TLS vulnerabilities if using outdated versions",
            "Web app attacks — SQLi, XSS if app is vulnerable",
        ],
        "if_closed": "HTTPS websites stop loading",
        "recommendation": "KEEP — ensure TLS 1.2+ only and valid certificate",
    },
    445: {
        "name": "SMB",
        "risk": "CRITICAL",
        "opened_by": "System (Windows kernel, PID 4)",
        "why_open": "Windows file sharing, network drives, printer sharing",
        "attacks": [
            "EternalBlue (MS17-010) — used by WannaCry ransomware",
            "NotPetya — destructive ransomware spread entirely via SMB",
            "Brute force — guess credentials to access shared files",
            "Pass-the-hash — reuse captured NTLM hashes",
            "SMB relay — intercept and relay authentication",
        ],
        "if_closed": "Windows file sharing, mapped drives, some printers stop",
        "recommendation": "BLOCK from internet — keep on local network only",
    },
    1433: {
        "name": "MSSQL",
        "risk": "CRITICAL",
        "opened_by": "SQL Server (sqlservr.exe)",
        "why_open": "Microsoft SQL Server database accepting connections",
        "attacks": [
            "Brute force — password guessing on SA (admin) account",
            "xp_cmdshell — execute OS commands directly from SQL",
            "Data exfiltration — direct access to all database contents",
        ],
        "if_closed": "Remote database connections stop",
        "recommendation": "CLOSE from internet — only allow specific trusted IPs",
    },
    3306: {
        "name": "MySQL",
        "risk": "CRITICAL",
        "opened_by": "mysqld.exe (MySQL Server)",
        "why_open": "MySQL database accepting network connections",
        "attacks": [
            "Brute force — attack root account",
            "Data theft — full database dump if credentials obtained",
            "CVE exploits — several critical MySQL RCE vulnerabilities",
        ],
        "if_closed": "Remote MySQL connections stop — local still works",
        "recommendation": "CLOSE from internet — bind to 127.0.0.1 in my.ini",
    },
    3389: {
        "name": "RDP",
        "risk": "CRITICAL",
        "opened_by": "svchost.exe (TermService)",
        "why_open": "Windows Remote Desktop GUI access",
        "attacks": [
            "BlueKeep (CVE-2019-0708) — unauthenticated RCE, wormable",
            "Brute force — most attacked port on the internet",
            "DejaBlue — similar to BlueKeep, affects newer Windows",
            "Credential stuffing — leaked passwords tried automatically",
        ],
        "if_closed": "Windows Remote Desktop stops working",
        "recommendation": "CLOSE from internet — use VPN first, then RDP",
    },
    5432: {
        "name": "PostgreSQL",
        "risk": "CRITICAL",
        "opened_by": "postgres.exe (PostgreSQL Server)",
        "why_open": "PostgreSQL database accepting connections",
        "attacks": [
            "Brute force — attack postgres superuser account",
            "COPY FILE — read/write arbitrary files on server",
            "Data exfiltration — full database accessible",
        ],
        "if_closed": "Remote PostgreSQL connections stop",
        "recommendation": "CLOSE from internet — bind to 127.0.0.1 in postgresql.conf",
    },
    5900: {
        "name": "VNC",
        "risk": "CRITICAL",
        "opened_by": "VNC server (RealVNC, TightVNC, UltraVNC)",
        "why_open": "Remote desktop access via VNC protocol",
        "attacks": [
            "No auth — many VNC installs have no password",
            "Weak auth — VNC uses weak DES-based auth, easily cracked",
            "Brute force — no lockout on many VNC implementations",
        ],
        "if_closed": "VNC remote access stops",
        "recommendation": "CLOSE — use RDP or SSH tunnelled VNC instead",
    },
    8080: {
        "name": "HTTP Alternate",
        "risk": "MEDIUM",
        "opened_by": "Development web server, proxy, or application server",
        "why_open": "Alternative HTTP — often dev servers or proxies",
        "attacks": [
            "Dev server exposed — often no auth, debug mode enabled",
            "Admin panels — many apps expose admin on 8080",
        ],
        "if_closed": "App running on port 8080 stops being accessible",
        "recommendation": "CLOSE if development server — never expose publicly",
    },
}

RISK_ORDER  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "OK": 5}
RISK_COLOR  = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
               "LOW": "green", "INFO": "dim", "OK": "green"}
RISK_EMOJI  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪", "OK": "🟢"}


class PortScanner:
    def __init__(self, target: str, db=None):
        self.target = target
        self.db     = db
        self.nm     = nmap.PortScanner()
        self.threat = ThreatLookup()
        self.cve_lookup = CVELookup()

    def resolve_host(self):
        try:
            ip       = socket.gethostbyname(self.target)
            hostname = socket.getfqdn(self.target)
            return ip, hostname
        except socket.gaierror:
            return None, None

    # ── Phase 1: fast sweep — find open ports only ──────────────────────
    def fast_sweep(self, ip: str) -> list:
        console.print("[dim]Phase 1 — Fast sweep across all 65535 ports...[/dim]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[purple]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("Sweeping ports 1–65535", total=None)
            self.nm.scan(hosts=ip, arguments="-p 1-65535 --open -T4 --min-rate=1000")
            progress.update(task, completed=True)

        open_ports = []
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                open_ports = sorted(self.nm[host][proto].keys())

        console.print(f"[green]Phase 1 complete — {len(open_ports)} open port(s) found[/green]")
        return open_ports

    # ── Phase 2: deep scan — service detection on open ports only ───────
    def deep_scan(self, ip: str, open_ports: list) -> list:
        if not open_ports:
            return []

        port_str = ",".join(str(p) for p in open_ports)
        console.print(f"[dim]Phase 2 — Deep service scan on {len(open_ports)} open port(s)...[/dim]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[purple]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("Detecting services and versions", total=None)
            self.nm.scan(hosts=ip, arguments=f"-sV -p {port_str} --open")
            progress.update(task, completed=True)

        results = []
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                for port in sorted(self.nm[host][proto].keys()):
                    info    = self.nm[host][proto][port]
                    service = info.get("name", "unknown")
                    state   = info.get("state", "unknown")
                    product = f"{info.get('product','')} {info.get('version','')}".strip()

                    vuln_data     = VULNERABLE_PORTS.get(port)
                    is_vulnerable = vuln_data is not None
                    risk          = vuln_data["risk"] if vuln_data else "OK"
                    vuln_reason   = vuln_data["recommendation"] if vuln_data else None

                    results.append({
                        "port":          port,
                        "proto":         proto,
                        "state":         state,
                        "service":       service,
                        "product":       product,
                        "is_vulnerable": is_vulnerable,
                        "risk":          risk,
                        "vuln_data":     vuln_data,
                        "vuln_reason":   vuln_reason,
                        "ip":            ip,
                        "hostname":      "",
                        "target":        self.target,
                        "scanned_at":    datetime.datetime.now().isoformat(),
                    })

        return results

    # ── Enrich results with CVE data ──────────────────────────────────
    def enrich_with_cves(self, results: list) -> list:
        """Query NVD for CVEs related to discovered services"""
        console.print("\n[dim]Enriching results with CVE data...[/dim]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("Querying NVD...", total=len(results))
            
            for result in results:
                # Search by service name first
                if result.get("service") and result["service"] != "unknown":
                    cves = self.cve_lookup.search_by_keyword(result["service"])
                    result["cves"] = cves
                # Also search by product if available
                elif result.get("product") and result["product"] != "unknown":
                    cves = self.cve_lookup.search_by_keyword(result["product"])
                    result["cves"] = cves
                else:
                    result["cves"] = []
                
                progress.update(task, advance=1)
        
        return results

    # ── Phase 3: display — grouped by risk, not a flat 1000-row table ───
    def display(self, results: list):
        if not results:
            console.print("[yellow]No open ports found.[/yellow]")
            return

        # Sort by risk level
        results.sort(key=lambda r: RISK_ORDER.get(r["risk"], 99))

        # Group by risk
        groups = {}
        for r in results:
            groups.setdefault(r["risk"], []).append(r)

        # ── Risk summary bar ────────────────────────────────────────────
        console.print()
        summary_parts = []
        for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "OK"]:
            count = len(groups.get(risk, []))
            if count:
                color = RISK_COLOR[risk]
                emoji = RISK_EMOJI[risk]
                summary_parts.append(f"[{color}]{emoji} {risk}: {count}[/{color}]")

        console.print("  " + "   ".join(summary_parts))
        console.print(f"  [dim]Total open ports: {len(results)}[/dim]\n")

        # ── CRITICAL — full panel with attack details ───────────────────
        if "CRITICAL" in groups:
            console.print("[bold red]━━━ CRITICAL RISK — Immediate action required ━━━[/bold red]\n")
            for r in groups["CRITICAL"]:
                self._print_detail_panel(r)

        # ── HIGH — panel with attacks ───────────────────────────────────
        if "HIGH" in groups:
            console.print("[red]━━━ HIGH RISK ━━━[/red]\n")
            for r in groups["HIGH"]:
                self._print_detail_panel(r)

        # ── MEDIUM — compact table ──────────────────────────────────────
        if "MEDIUM" in groups:
            console.print("[yellow]━━━ MEDIUM RISK ━━━[/yellow]")
            self._print_compact_table(groups["MEDIUM"], "yellow")

        # ── LOW / OK — minimal summary ──────────────────────────────────
        safe = groups.get("LOW", []) + groups.get("OK", [])
        if safe:
            console.print(f"\n[green]━━━ LOW / OK — {len(safe)} port(s) — no immediate action needed ━━━[/green]")
            self._print_compact_table(safe, "green")

    def _print_detail_panel(self, r: dict):
        vd    = r["vuln_data"]
        color = RISK_COLOR.get(r["risk"], "white").replace("bold ", "")
        attacks_text = "\n".join(f"  • {a}" for a in vd["attacks"])

        content = (
            f"[dim]Service:[/dim]      {r['service']}  {('— ' + r['product']) if r['product'] else ''}\n"
            f"[dim]Opened by:[/dim]    {vd['opened_by']}\n"
            f"[dim]Why open:[/dim]     {vd['why_open']}\n\n"
            f"[bold]Possible attacks:[/bold]\n[red]{attacks_text}[/red]\n\n"
            f"[dim]If you close it:[/dim]  {vd['if_closed']}\n\n"
            f"[bold]Action:[/bold] [{RISK_COLOR[r['risk']]}]{vd['recommendation']}[/{RISK_COLOR[r['risk']]}]"
        )
        
        # Add CVE information if available
        if r.get("cves"):
            cve_text = "\n[bold]Known CVEs:[/bold]\n"
            for cve in r["cves"][:3]:  # Show top 3 CVEs
                cve_text += (
                    f"  • [bold]{cve['cve_id']}[/bold] (CVSS: {cve['cvss_score']})\n"
                    f"    {cve['description'][:80]}...\n"
                    f"    [dim]{cve['url']}[/dim]\n"
                )
            content += "\n" + cve_text

        console.print(Panel(
            content,
            title=f"[{RISK_COLOR[r['risk']]}] {RISK_EMOJI[r['risk']]}  Port {r['port']} — {vd['name']} — {r['risk']} RISK [/{RISK_COLOR[r['risk']]}]",
            border_style=color,
            expand=False,
            width=88,
        ))
        console.print()

    def _print_compact_table(self, rows: list, color: str):
        table = Table(border_style=color, show_lines=False, box=box.SIMPLE)
        table.add_column("Port",    width=7,  style="cyan")
        table.add_column("Service", width=16)
        table.add_column("Product", width=28, style="dim")
        table.add_column("Risk",    width=10)
        table.add_column("Action",  width=40)

        for r in rows:
            vd    = r["vuln_data"]
            rc    = RISK_COLOR.get(r["risk"], "white")
            action = vd["recommendation"] if vd else "No known vulnerability"
            table.add_row(
                str(r["port"]),
                r["service"],
                r["product"] or "—",
                f"[{rc}]{r['risk']}[/{rc}]",
                action,
            )
        console.print(table)

    def scan(self, port_range=None):
        ip, hostname = self.resolve_host()
        if not ip:
            console.print(f"[red]Could not resolve host: {self.target}[/red]")
            return []

        console.print(f"[dim]Resolved → IP: {ip}  |  Hostname: {hostname}[/dim]\n")

        # Choose scan mode
        if port_range:
            # Manual range — single deep scan
            console.print(f"[dim]Scanning ports {port_range}...[/dim]")
            self.nm.scan(hosts=ip, arguments=f"-sV -p {port_range} --open")
            results = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    for port in sorted(self.nm[host][proto].keys()):
                        info    = self.nm[host][proto][port]
                        service = info.get("name", "unknown")
                        product = f"{info.get('product','')} {info.get('version','')}".strip()
                        vuln_data     = VULNERABLE_PORTS.get(port)
                        is_vulnerable = vuln_data is not None
                        risk          = vuln_data["risk"] if vuln_data else "OK"
                        vuln_reason   = vuln_data["recommendation"] if vuln_data else None
                        results.append({
                            "port": port, "proto": proto,
                            "state": "open", "service": service,
                            "product": product, "is_vulnerable": is_vulnerable,
                            "risk": risk, "vuln_data": vuln_data,
                            "vuln_reason": vuln_reason,
                            "ip": ip, "hostname": hostname,
                            "target": self.target,
                            "scanned_at": datetime.datetime.now().isoformat(),
                        })
            return results
        else:
            # Full 2-phase scan
            open_ports = self.fast_sweep(ip)
            if not open_ports:
                console.print("[green]No open ports found on this host.[/green]")
                return []
            return self.deep_scan(ip, open_ports)

    def run(self):
        console.print(f"\n[bold purple]Veilguard Port Scanner[/bold purple] — {self.target}\n")

        console.print("Scan mode:")
        console.print("  [cyan]1[/cyan] — Quick scan (common ports 1–1024)")
        console.print("  [cyan]2[/cyan] — Full scan (all 65535 ports, recommended)")
        console.print("  [cyan]3[/cyan] — Custom range")

        mode = input("\n> ").strip()

        if mode == "1":
            results = self.scan(port_range="1-1024")
        elif mode == "2":
            results = self.scan()
        elif mode == "3":
            port_range = input("Enter range (e.g. 8000-9000): ").strip()
            results = self.scan(port_range=port_range)
        else:
            console.print("[red]Invalid choice[/red]")
            return []

        # Enrich results with CVE data
        if results:
            results = self.enrich_with_cves(results)

        self.display(results)

        if self.db and results:
            self.db.save_scan(results)
            console.print("\n[dim]Results saved to database.[/dim]")

        return results