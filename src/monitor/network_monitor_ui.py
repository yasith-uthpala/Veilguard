from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from rich import box
from datetime import datetime
import threading
import time
import os
import sys

console = Console()

# ---------------------------------------------------------------------------
# Lazy imports — graceful degradation if packages not installed
# ---------------------------------------------------------------------------
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from src.scanner.threat_lookup import ThreatLookup, GeoIPLookup
    _TI_AVAILABLE = True
except ImportError:
    _TI_AVAILABLE = False

try:
    from src.monitor.notifier import notifier as _notifier
except ImportError:
    from monitor.notifier import notifier as _notifier


# ---------------------------------------------------------------------------
# Helper: check private IP without importing GeoIPLookup
# ---------------------------------------------------------------------------
def _is_private(ip: str) -> bool:
    try:
        p = [int(x) for x in ip.split(".")]
        a, b = p[0], p[1]
        return (a == 127 or a == 10 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168) or
                (a == 169 and b == 254))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# NetworkMonitorUI  — drop-in replacement keeping same public API
# ---------------------------------------------------------------------------
class NetworkMonitorUI:
    """
    Simple, reliable UI for network monitor.

    Same interface as before — just call display_live() or display_summary().

    New features added on top:
      1. GeoIP  — flag + city + ISP per remote IP (ip-api.com, free, no key)
      2. VirusTotal — malicious verdict per IP (needs VIRUSTOTAL_API_KEY in .env)
      3. Toast notifications — fires on malicious IP / high-risk country / spike
    """

    def __init__(self, monitor, refresh_interval: int = 2):
        self.monitor = monitor
        self.refresh_interval = refresh_interval
        self.console = console

        if _TI_AVAILABLE:
            self.vt    = ThreatLookup()
            self.geoip = GeoIPLookup()
        else:
            self.vt    = None
            self.geoip = None

        self._geo:      dict = {}
        self._vt_res:   dict = {}
        self._geo_done: set  = set()
        self._vt_done:  set  = set()
        self._alerted:  set  = set()
        self._queue:    list = []
        self._qlock          = threading.Lock()

        threading.Thread(target=self._worker, daemon=True).start()

    # ── background enrichment ──────────────────────────────────────────────

    def _enqueue(self, ip: str):
        if not ip or ip in ("—", "N/A") or _is_private(ip):
            return
        with self._qlock:
            if ip not in self._geo_done and ip not in self._queue:
                self._queue.append(ip)

    def _worker(self):
        while True:
            ip = None
            with self._qlock:
                if self._queue:
                    ip = self._queue.pop(0)

            if ip and self.geoip:
                # GeoIP — fast
                if ip not in self._geo_done:
                    geo = self.geoip.lookup(ip)
                    self._geo[ip] = geo
                    self._geo_done.add(ip)
                    if geo.get("is_high_risk") and ip not in self._alerted:
                        self._alerted.add(ip)
                        _notifier.send(
                            f"Veilguard — High-Risk Country: {geo.get('country','?')}",
                            f"Connection detected to {ip}",
                            key=f"geo:{ip}"
                        )

                # VirusTotal — rate-limited
                if ip not in self._vt_done:
                    if self.vt and self.vt.api_key:
                        vt = self.vt.lookup_ip(ip)
                        self._vt_res[ip] = vt
                        verdict = vt.get("verdict", "clean")
                        if verdict in ("malicious", "suspicious") and ip not in self._alerted:
                            self._alerted.add(ip)
                            _notifier.send(
                                "Veilguard — Malicious IP Detected",
                                f"{ip} — {vt.get('verdict_label', verdict)}",
                                key=f"vt:{ip}"
                            )
                    self._vt_done.add(ip)
            else:
                time.sleep(0.5)

    # ── label helpers ──────────────────────────────────────────────────────

    def _geo_str(self, ip: str) -> str:
        if not self.geoip:
            return "—"
        geo = self._geo.get(ip)
        if geo is None:
            return "resolving…"
        if "error" in geo or geo.get("is_private"):
            return "Private"
        flag = geo.get("flag", "")
        city = geo.get("city", "?")
        cc   = geo.get("country_code", "?")
        isp  = geo.get("isp", "")[:20]
        out  = f"{flag} {city}, {cc}"
        if isp:
            out += f" — {isp}"
        return out

    def _geo_style(self, ip: str) -> str:
        return "bold red" if self._geo.get(ip, {}).get("is_high_risk") else "white"

    def _vt_str(self, ip: str) -> str:
        if not self.vt:
            return "—"
        if not self.vt.api_key:
            return "no key in .env"
        vt = self._vt_res.get(ip)
        if vt is None:
            return "checking…"
        if "error" in vt:
            return "error"
        return vt.get("verdict_label", vt.get("verdict", "clean"))

    def _vt_style(self, ip: str) -> str:
        v = self._vt_res.get(ip, {}).get("verdict", "clean")
        return {"malicious": "bold red", "suspicious": "bold yellow", "clean": "green"}.get(v, "dim")

    # ── UI builder ─────────────────────────────────────────────────────────

    def _build_ui(self):
        stats         = self.monitor.get_live_stats()
        packet_count  = stats.get("packet_count", 0)
        alert_count   = len(stats.get("recent_alerts", []))
        process_count = stats.get("total_processes_monitored", 0)
        uptime        = stats.get("uptime", 0)

        renderables = []

        # ── Header ─────────────────────────────────────────────────────
        geo_done  = len(self._geo_done)
        vt_hits   = sum(1 for r in self._vt_res.values()
                        if r.get("verdict") in ("malicious", "suspicious"))
        hr_hits   = sum(1 for r in self._geo.values() if r.get("is_high_risk"))

        header = (
            f"Veilguard Network Monitor  |  "
            f"Packets: {packet_count}  |  "
            f"Processes: {process_count}  |  "
            f"Alerts: {alert_count}  |  "
            f"Uptime: {uptime:.0f}s  |  "
            f"IPs resolved: {geo_done}"
        )
        if hr_hits:
            header += f"  |  [bold red]High-risk: {hr_hits}[/bold red]"
        if self.vt and self.vt.api_key:
            header += f"  |  VT: {len(self._vt_done)} checked"
            if vt_hits:
                header += f"  |  [bold red]Flagged: {vt_hits}[/bold red]"
        else:
            header += "  |  [dim]VT: add VIRUSTOTAL_API_KEY to .env[/dim]"

        renderables.append(Panel(header, style="bold cyan"))

        # ── Bandwidth table (same as original) ─────────────────────────
        if stats.get("top_processes"):
            table = Table(
                title="Top Processes by Bandwidth",
                box=box.ROUNDED, border_style="green"
            )
            table.add_column("PID",      style="cyan",    width=8)
            table.add_column("Process",  style="yellow",  width=25)
            table.add_column("Total",    style="green",   width=12)
            table.add_column("Upload",   style="blue",    width=12)
            table.add_column("Download", style="magenta", width=12)

            bw = stats.get("bandwidth_data", {})
            for name, pid, total_bytes in stats["top_processes"][:10]:
                proc  = bw.get(pid, {})
                total_mb = total_bytes / (1024 * 1024)
                up_mb    = proc.get("bytes_out", 0) / (1024 * 1024)
                dn_mb    = proc.get("bytes_in",  0) / (1024 * 1024)
                table.add_row(
                    str(pid), name[:25],
                    f"{total_mb:.2f} MB",
                    f"{up_mb:.2f} MB",
                    f"{dn_mb:.2f} MB",
                )
            renderables.append(table)
        else:
            renderables.append(Panel(
                "[yellow]No processes detected yet. "
                "Try opening a browser or running: ping 8.8.8.8[/yellow]"
            ))

        # ── Connections table — NEW columns: Location + VT ─────────────
        try:
            import psutil
            conns = psutil.net_connections(kind="inet")

            ctable = Table(
                title=f"Active Connections  [{datetime.now().strftime('%H:%M:%S')}]",
                box=box.ROUNDED, border_style="purple"
            )
            ctable.add_column("PID",      width=7,  style="dim")
            ctable.add_column("Process",  width=18)
            ctable.add_column("Status",   width=13)
            ctable.add_column("Remote",   width=22)
            ctable.add_column("Location", width=30)   # GeoIP
            ctable.add_column("VT",       width=22)   # VirusTotal

            STATUS_CLR = {
                "ESTABLISHED": "green", "LISTEN": "cyan",
                "TIME_WAIT": "yellow",  "CLOSE_WAIT": "yellow",
                "SYN_SENT": "red",      "NONE": "dim",
            }

            shown = 0
            for conn in conns:
                if shown >= 20:
                    break
                status = conn.status or "NONE"
                rip    = conn.raddr.ip   if conn.raddr else None
                rport  = conn.raddr.port if conn.raddr else None
                remote = f"{rip}:{rport}" if rip else "—"

                if rip:
                    self._enqueue(rip)

                pid = conn.pid
                try:
                    p    = psutil.Process(pid) if pid else None
                    name = p.name() if p else "system"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    name = "unknown"

                vt_verdict = self._vt_res.get(rip, {}).get("verdict", "") if rip else ""
                geo_hr     = self._geo.get(rip, {}).get("is_high_risk", False) if rip else False
                name_style = ("bold red"    if vt_verdict == "malicious" else
                              "bold yellow" if vt_verdict == "suspicious" or geo_hr else
                              "cyan")

                ctable.add_row(
                    str(pid or "—"),
                    Text(name[:18], style=name_style),
                    Text(status, style=STATUS_CLR.get(status, "white")),
                    remote,
                    Text(self._geo_str(rip), style=self._geo_style(rip)) if rip else Text("—", style="dim"),
                    Text(self._vt_str(rip),  style=self._vt_style(rip))  if rip else Text("—", style="dim"),
                )
                shown += 1

            renderables.append(ctable)

        except Exception:
            pass   # silently skip if psutil unavailable

        # ── Alerts table (same as original + toast notifications) ──────
        if stats.get("recent_alerts"):
            at = Table(title="Recent Alerts", box=box.ROUNDED, border_style="red")
            at.add_column("Time",    width=10)
            at.add_column("Type",    style="red",  width=18)
            at.add_column("Process", width=20)
            at.add_column("Details", width=40)

            for alert in stats["recent_alerts"][-5:]:
                def _g(a, k, d="N/A"):
                    return a.get(k, d) if isinstance(a, dict) else getattr(a, k, d)

                ts      = _g(alert, "timestamp", None)
                ts_str  = ts.strftime("%H:%M:%S") if hasattr(ts, "strftime") else str(ts or "N/A")
                atype   = _g(alert, "alert_type",   "UNKNOWN")
                pname   = _g(alert, "process_name", "N/A")
                details = str(_g(alert, "details",  "N/A"))[:40]
                sev     = _g(alert, "severity",     "")
                bps     = float(_g(alert, "bytes_per_second", 0))

                at.add_row(ts_str, atype, pname, details)

                if sev in ("critical", "high"):
                    mbps = bps / (1024 * 1024)
                    if atype == "exfiltration":
                        _notifier.send("Veilguard — Exfiltration Suspected",
                                       f"{pname}: {mbps:.1f} MB/s outbound",
                                       key=f"exfil:{pname}")
                    elif atype == "spike":
                        _notifier.send("Veilguard — Bandwidth Spike",
                                       f"{pname}: {mbps:.1f} MB/s",
                                       key=f"spike:{pname}")
                    elif atype == "suspicious_port":
                        _notifier.send("Veilguard — Suspicious Port",
                                       f"{pname}: {details}",
                                       key=f"sport:{pname}")

            renderables.append(at)
        else:
            renderables.append(Panel("[green]No alerts[/green]"))

        # ── Stats panel (same as original) ─────────────────────────────
        stat_text = (
            f"\n"
            f"  Total Processes:  {process_count}\n"
            f"  Total Packets:    {packet_count}\n"
            f"  Total Alerts:     {alert_count}\n"
            f"  Capture Duration: {uptime:.1f}s\n"
            f"  IPs geo-resolved: {len(self._geo_done)}\n"
        )
        if self.vt and self.vt.api_key:
            stat_text += f"  IPs VT-checked:   {len(self._vt_done)}\n"
        renderables.append(Panel(stat_text, title="Stats", border_style="blue"))

        renderables.append(Panel("[dim]Press Ctrl+C to exit[/dim]"))

        return Group(*renderables)

    # ── public methods — same signature as original ────────────────────────

    def display_live(self, update_interval=2):
        """Display live network stats — identical call signature as before."""
        if not _TI_AVAILABLE:
            console.print("[yellow]Install threat intel: pip install plyer win10toast[/yellow]")
        elif self.vt and not self.vt.api_key:
            console.print("[yellow]Add VIRUSTOTAL_API_KEY=your_key to .env for VT lookups[/yellow]")

        try:
            with Live(
                self._build_ui(),
                refresh_per_second=1 / update_interval,
                console=console
            ) as live:
                while True:
                    time.sleep(update_interval)
                    live.update(self._build_ui())
        except KeyboardInterrupt:
            console.print("\n[yellow]Monitoring stopped[/yellow]")

    def display_summary(self):
        """Display summary report — identical as original."""
        stats = self.monitor.get_live_stats()
        console.print("\n[bold cyan]=== Network Monitor Summary ===[/bold cyan]\n")
        console.print(f"Packets captured:   {stats['packet_count']}")
        console.print(f"Processes detected: {stats['total_processes_monitored']}")
        console.print(f"Uptime:             {stats['uptime']:.2f}s")
        console.print(f"Alerts:             {len(stats['recent_alerts'])}\n")

        if stats["top_processes"]:
            table = Table(title="Top Processes", box=box.ROUNDED)
            table.add_column("PID",     style="cyan")
            table.add_column("Process", style="yellow")
            table.add_column("Bytes",   style="green")
            for name, pid, total_bytes in stats["top_processes"][:10]:
                mb = total_bytes / (1024 * 1024)
                table.add_row(str(pid), name, f"{mb:.2f} MB")
            console.print(table)

    def _format_uptime(self, uptime: float) -> str:
        """Format uptime into human-readable string."""
        if uptime < 60:
            return f"{uptime:.1f}s"
        m, s = divmod(int(uptime), 60)
        return f"{m}m {s}s"

    def _create_stats_panel(self):
        """Create Rich Panel displaying monitoring statistics."""
        stats = self.monitor.get_live_stats()
        stat_text = (
            f"  Total Processes:  {stats.get('total_processes_monitored', 0)}\n"
            f"  Total Packets:    {stats.get('packet_count', 0)}\n"
            f"  Total Alerts:     {len(stats.get('recent_alerts', []))}\n"
            f"  Capture Duration: {self._format_uptime(stats.get('uptime', 0))}\n"
            f"  IPs geo-resolved: {len(self._geo_done)}\n"
        )
        if self.vt and self.vt.api_key:
            stat_text += f"  IPs VT-checked:   {len(self._vt_done)}\n"
        return Panel(stat_text, title="Stats", border_style="blue")

    def _create_bandwidth_table(self):
        """Create Rich Table displaying top processes by bandwidth."""
        stats = self.monitor.get_live_stats()
        table = Table(
            title="Top Processes by Bandwidth",
            box=box.ROUNDED, border_style="green"
        )
        table.add_column("PID", style="cyan", width=8)
        table.add_column("Process", style="yellow", width=25)
        table.add_column("Total", style="green", width=12)
        table.add_column("Upload", style="blue", width=12)
        table.add_column("Download", style="magenta", width=12)

        bw = stats.get("bandwidth_data", {})
        for name, pid, total_bytes in stats.get("top_processes", [])[:10]:
            proc = bw.get(pid, {})
            total_mb = total_bytes / (1024 * 1024)
            up_mb = proc.get("bytes_out", 0) / (1024 * 1024)
            dn_mb = proc.get("bytes_in", 0) / (1024 * 1024)
            table.add_row(
                str(pid), name[:25],
                f"{total_mb:.2f} MB",
                f"{up_mb:.2f} MB",
                f"{dn_mb:.2f} MB",
            )
        return table

    def display_alerts_report(self):
        """Display table of recorded security alerts."""
        stats = self.monitor.get_live_stats()
        alerts = stats.get("recent_alerts", [])
        if not alerts:
            console.print("[green]No alerts detected during monitoring session.[/green]")
            return

        at = Table(title="Security & Anomaly Alerts", box=box.ROUNDED, border_style="red")
        at.add_column("Time", width=10)
        at.add_column("Severity", width=10)
        at.add_column("Type", style="red", width=18)
        at.add_column("Process", width=20)
        at.add_column("Details", width=45)

        for alert in alerts:
            def _g(a, k, d="N/A"):
                return a.get(k, d) if isinstance(a, dict) else getattr(a, k, d)

            ts = _g(alert, "timestamp", None)
            ts_str = ts.strftime("%H:%M:%S") if hasattr(ts, "strftime") else str(ts or "N/A")
            sev = str(_g(alert, "severity", "medium")).upper()
            atype = str(_g(alert, "alert_type", "UNKNOWN"))
            pname = str(_g(alert, "process_name", "N/A"))
            details = str(_g(alert, "details", "N/A"))

            sev_color = "red" if sev in ("CRITICAL", "HIGH") else "yellow"
            at.add_row(ts_str, f"[{sev_color}]{sev}[/{sev_color}]", atype, pname, details)

        console.print(at)

    def display_process_details(self, pid: int):
        """Display detailed bandwidth and connection info for a specific PID."""
        proc = self.monitor.get_process_details(pid)
        if not proc:
            console.print(f"[yellow]No network activity recorded for PID {pid}[/yellow]")
            return

        total_mb = proc.get("total_bytes", 0) / (1024 * 1024)
        up_mb = proc.get("bytes_out", 0) / (1024 * 1024)
        dn_mb = proc.get("bytes_in", 0) / (1024 * 1024)

        console.print(Panel(
            f"[bold cyan]Process Details — {proc.get('name', 'Unknown')} (PID: {pid})[/bold cyan]\n"
            f"Executable: [dim]{proc.get('executable', 'N/A')}[/dim]\n\n"
            f"Total Transfer: [green]{total_mb:.2f} MB[/green] "
            f"(Upload: [blue]{up_mb:.2f} MB[/blue], Download: [magenta]{dn_mb:.2f} MB[/magenta])\n"
            f"Packets: {proc.get('packets_in', 0)} in / {proc.get('packets_out', 0)} out\n"
            f"Ports Used: {list(proc.get('ports', []))}\n"
            f"Remote Peers: {len(proc.get('connections', {}))}",
            border_style="cyan"
        ))

    def display_simple(self, duration: int = 30):
        """Run simple timed capture with countdown timer."""
        console.print(f"[cyan]Capturing traffic for {duration} seconds...[/cyan]")
        self.monitor.start()
        try:
            for remaining in range(duration, 0, -1):
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Capture interrupted by user.[/yellow]")
        finally:
            self.monitor.stop()
