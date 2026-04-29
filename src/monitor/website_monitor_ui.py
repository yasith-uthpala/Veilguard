"""
Website Monitor UI - Rich dashboard for website traffic visualization and blocking
"""

from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from datetime import datetime
from src.monitor.website_monitor import DNSCapture
import time


class WebsiteMonitorUI:
    """Rich terminal UI for website monitoring"""

    def __init__(self, dns_capture: DNSCapture):
        self.dns = dns_capture
        self.console = Console()
        self.start_time = datetime.now()

    def _format_time_diff(self, dt: datetime) -> str:
        diff = datetime.now() - dt
        if diff.total_seconds() < 60:
            return f"{int(diff.total_seconds())}s ago"
        elif diff.total_seconds() < 3600:
            return f"{int(diff.total_seconds() / 60)}m ago"
        return f"{int(diff.total_seconds() / 3600)}h ago"

    def _severity_tag(self, level: str) -> str:
        colors = {
            "critical": "[bold red]",
            "high": "[red]",
            "medium": "[yellow]",
            "low": "[green]",
            "safe": "[green]",
        }
        color = colors.get(level, "[white]")
        return f"{color}{level.upper()}[/]"

    def _build_ui(self) -> Group:
        uptime = datetime.now() - self.start_time
        h, rem = divmod(int(uptime.total_seconds()), 3600)
        m, s = divmod(rem, 60)
        uptime_str = f"{h:02}:{m:02}:{s:02}"

        stats = self.dns.get_stats()
        feed_count = stats.get("feed_domains_loaded", 0)

        # Header
        header = Panel(
            f"[bold cyan]🌐 Website Monitor[/bold cyan] | "
            f"[yellow]Visited: {stats['total_domains_visited']}[/yellow] | "
            f"[red]Blocked: {stats['blocked_attempts']}[/red] | "
            f"[green]Safe: {stats['safe_visits']}[/green] | "
            f"[magenta]Threat DB: {feed_count:,} domains[/magenta] | "
            f"[dim]Uptime: {uptime_str}[/dim]",
            border_style="cyan",
            style="bold white on black",
        )

        # Recent Visited Domains
        # UPDATED: Limit increased to 30 to show more history
        visited_table = Table(
            title="🕐 Recent Visited Domains (Last 30)", border_style="blue"
        )
        visited_table.add_column("Time", style="dim", width=10)
        visited_table.add_column("Domain", style="cyan", width=40)
        visited_table.add_column("Process", style="green", width=20)
        visited_table.add_column("Status", width=12)

        for visit in self.dns.get_recent_domains(limit=30):
            status = (
                "[red]● BLOCKED[/red]" if visit.is_blocked
                else "[green]● SAFE[/green]"
            )
            visited_table.add_row(
                self._format_time_diff(visit.timestamp),
                visit.domain[:40],
                (visit.process_name or "Unknown")[:20],
                status,
            )

        # Blocked Sites
        # UPDATED: Limit increased to 15 to show more blocked attempts
        blocked_table = Table(
            title="🚫 Blocked Malicious Sites (Last 15)", border_style="red"
        )
        blocked_table.add_column("Domain", style="red", width=35)
        blocked_table.add_column("Source", style="magenta", width=12)
        blocked_table.add_column("Threat", style="yellow", width=12)
        blocked_table.add_column("Severity", width=12)
        blocked_table.add_column("Process", style="green", width=15)
        blocked_table.add_column("Time", style="dim", width=10)

        for visit in self.dns.get_blocked_domains(limit=15):
            blocked_table.add_row(
                visit.domain[:35],
                "Feed" if visit.threat_type in ("malware", "phishing", "spam")
                else "Local",
                visit.threat_type or "Unknown",
                self._severity_tag(visit.threat_level),
                (visit.process_name or "Unknown")[:15],
                self._format_time_diff(visit.timestamp),
            )

        # Threat Breakdown
        threat_table = Table(
            title="📊 Threat Breakdown", border_style="yellow"
        )
        threat_table.add_column("Type", style="yellow", width=15)
        threat_table.add_column("Count", style="cyan", width=8)
        threat_table.add_column("Bar", style="red", width=30)

        breakdown = stats.get("threat_breakdown", {})
        max_count = max(breakdown.values(), default=1)
        for t_type, count in sorted(
            breakdown.items(), key=lambda x: x[1], reverse=True
        ):
            bar = "█" * int((count / max_count) * 25)
            threat_table.add_row(t_type.upper(), str(count), bar)

        # Statistics
        stats_panel = Panel(
            f"[bold]Packets Captured:[/bold]     {stats['packets_captured']}\n"
            f"[bold]Unique Domains:[/bold]       {stats['total_domains_visited']}\n"
            f"[bold]Total Visits:[/bold]         {stats['total_visits']}\n"
            f"[bold]Blocked Rate:[/bold]         {stats['blocked_rate']}\n"
            f"[bold]Threat DB Size:[/bold]       [magenta]{feed_count:,} domains[/magenta]\n"
            f"[bold cyan]Status:[/bold cyan]               [green]● Monitoring Active[/green]",
            border_style="green",
            title="📈 Statistics",
        )

        instructions = Panel(
            "[dim]Press [bold]Ctrl+C[/bold] to stop  |  "
            "[green]●[/green] Safe  [red]●[/red] Blocked  |  "
            "Feeds: URLhaus · PhishTank · Spamhaus · Pi-hole  |  "
            "Auto-refreshes every 6h[/dim]",
            border_style="dim",
        )

        return Group(
            header,
            visited_table,
            blocked_table,
            threat_table,
            stats_panel,
            instructions,
        )

    def display_live(self, update_interval: int = 2):
        self.console.print(
            "[cyan]🌐 Starting Website Monitor...[/cyan]\n"
            "[dim]Loading threat intelligence feeds in background...[/dim]\n"
        )
        try:
            with Live(self._build_ui(), refresh_per_second=1) as live:
                while True:
                    live.update(self._build_ui())
                    time.sleep(update_interval)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]⏹ Stopping Website Monitor...[/yellow]")
            self.display_summary()

    def display_summary(self):
        stats = self.dns.get_stats()
        self.console.print(Panel(
            f"[bold]Website Monitoring Summary[/bold]\n\n"
            f"Unique Domains Visited : {stats['total_domains_visited']}\n"
            f"Total Visits           : {stats['total_visits']}\n"
            f"Packets Captured       : {stats['packets_captured']}\n"
            f"Blocked Attempts       : {stats['blocked_attempts']}\n"
            f"Safe Visits            : {stats['safe_visits']}\n"
            f"Blocked Rate           : {stats['blocked_rate']}\n"
            f"Threat DB Size         : {stats.get('feed_domains_loaded', 0):,} domains",
            border_style="purple",
            title="📋 Session Summary",
        ))

        if stats.get("threat_breakdown"):
            self.console.print("\n[bold]Threats Detected:[/bold]")
            for t_type, count in sorted(
                stats["threat_breakdown"].items(),
                key=lambda x: x[1],
                reverse=True,
            ):
                self.console.print(
                    f"  [red]•[/red] {t_type.upper()}: {count} attempt(s)"
                )