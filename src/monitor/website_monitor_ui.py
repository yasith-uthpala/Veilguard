"""
Website Monitor UI - Rich dashboard for website traffic visualization and blocking
Shows visited domains, blocked sites, threat alerts, and statistics
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.group import Group
from rich.layout import Layout
from rich.text import Text
from datetime import datetime, timedelta
from src.monitor.website_monitor import DNSCapture
import time


class WebsiteMonitorUI:
    """Rich terminal UI for website monitoring"""

    def __init__(self, dns_capture: DNSCapture):
        self.dns = dns_capture
        self.console = Console()
        self.start_time = datetime.now()

    def _format_time_diff(self, dt: datetime) -> str:
        """Format time difference from now"""
        diff = datetime.now() - dt
        if diff.total_seconds() < 60:
            return f"{int(diff.total_seconds())}s ago"
        elif diff.total_seconds() < 3600:
            return f"{int(diff.total_seconds() / 60)}m ago"
        else:
            return f"{int(diff.total_seconds() / 3600)}h ago"

    def _build_ui(self) -> Group:
        """Build the UI components"""
        uptime = datetime.now() - self.start_time
        uptime_str = f"{int(uptime.total_seconds())}s"

        stats = self.dns.get_stats()

        # Header Panel
        header_text = (
            f"[bold cyan]🌐 Website Monitor[/bold cyan] | "
            f"[yellow]Visited: {stats['total_domains_visited']}[/yellow] | "
            f"[red]Blocked: {stats['blocked_attempts']}[/red] | "
            f"[green]Safe: {stats['safe_visits']}[/green] | "
            f"[dim]Uptime: {uptime_str}[/dim]"
        )
        header = Panel(header_text, border_style="cyan", style="bold white on black")

        # Recent Visited Domains Table
        visited_table = Table(title="🕐 Recent Visited Domains", border_style="blue")
        visited_table.add_column("Time", style="dim")
        visited_table.add_column("Domain", style="cyan", width=40)
        visited_table.add_column("Process", style="green")
        visited_table.add_column("Status", style="yellow")

        recent = self.dns.get_recent_domains(limit=10)
        for visit in recent:
            status = f"[red]BLOCKED[/red]" if visit.is_blocked else "[green]✓[/green]"
            process = visit.process_name if visit.process_name else "N/A"
            visited_table.add_row(
                self._format_time_diff(visit.timestamp),
                visit.domain[:40],
                process[:20],
                status
            )

        # Blocked Sites Table
        blocked_table = Table(title="🚫 Blocked Malicious Sites", border_style="red")
        blocked_table.add_column("Domain", style="red")
        blocked_table.add_column("Threat Type", style="yellow")
        blocked_table.add_column("Severity", style="bright_red")
        blocked_table.add_column("Process", style="green")
        blocked_table.add_column("Time", style="dim")

        blocked = self.dns.get_blocked_domains()
        for visit in blocked[-5:]:  # Last 5 blocked attempts
            blocked_table.add_row(
                visit.domain,
                visit.threat_type or "Unknown",
                visit.threat_level.upper(),
                visit.process_name or "Unknown",
                self._format_time_diff(visit.timestamp)
            )

        # Threat Breakdown Table
        threat_table = Table(title="📊 Threat Breakdown", border_style="yellow")
        threat_table.add_column("Threat Type", style="yellow")
        threat_table.add_column("Count", style="cyan")

        for threat_type, count in stats.get("threat_breakdown", {}).items():
            threat_table.add_row(threat_type.upper(), str(count))

        # Statistics Panel
        stats_text = (
            f"[bold]Packets Captured:[/bold] {stats['packets_captured']}\n"
            f"[bold]Total Domains:[/bold] {stats['total_domains_visited']}\n"
            f"[bold]Total Visits:[/bold] {stats['total_visits']}\n"
            f"[bold]Blocked Rate:[/bold] {stats['blocked_rate']}\n"
            f"[bold cyan]Status:[/bold cyan] [green]●[/green] Monitoring Active"
        )
        stats_panel = Panel(stats_text, border_style="green", title="📈 Statistics")

        # Instructions Panel
        instructions = Panel(
            "[dim]Press Ctrl+C to stop monitoring\n"
            "🟢 = Safe, 🔴 = Blocked, 🟡 = Suspicious[/dim]",
            border_style="dim"
        )

        return Group(
            header,
            visited_table,
            blocked_table,
            threat_table,
            stats_panel,
            instructions
        )

    def display_live(self, update_interval: int = 2):
        """Display live monitoring dashboard"""
        self.console.print("[cyan]🌐 Starting Website Monitor...[/cyan]\n")

        try:
            with Live(self._build_ui(), refresh_per_second=1) as live:
                while True:
                    live.update(self._build_ui())
                    time.sleep(update_interval)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]⏹ Stopping Website Monitor...[/yellow]")

    def display_summary(self):
        """Display summary of monitoring results"""
        stats = self.dns.get_stats()

        self.console.print(Panel(
            f"[bold]Website Monitoring Summary[/bold]\n"
            f"Total Domains Visited: {stats['total_domains_visited']}\n"
            f"Total Visits: {stats['total_visits']}\n"
            f"Blocked Attempts: {stats['blocked_attempts']}\n"
            f"Safe Visits: {stats['safe_visits']}\n"
            f"Blocked Rate: {stats['blocked_rate']}",
            border_style="purple"
        ))

        # Show top threats
        if stats.get("threat_breakdown"):
            self.console.print("\n[bold]Top Threats:[/bold]")
            for threat_type, count in sorted(
                stats["threat_breakdown"].items(),
                key=lambda x: x[1],
                reverse=True
            ):
                self.console.print(f"  - {threat_type}: {count} attempts")
