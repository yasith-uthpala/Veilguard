import psutil
import socket
import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich import box
import time

console = Console()

SUSPICIOUS_PORTS = {4444, 1337, 31337, 5555, 6666, 7777, 9999, 8888}

STATUS_COLOR = {
    "ESTABLISHED": "green",
    "LISTEN":      "cyan",
    "TIME_WAIT":   "yellow",
    "CLOSE_WAIT":  "yellow",
    "SYN_SENT":    "red",
    "NONE":        "dim",
}

# Known safe system processes — reduce false positives
SYSTEM_PROCESSES = {
    "svchost.exe", "system", "lsass.exe", "wininit.exe",
    "services.exe", "smss.exe", "csrss.exe",
}


class ProcessMonitor:

    def snapshot(self):
        rows = []
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            console.print("[red]Run as Administrator for full process visibility.[/red]")
            return rows

        for conn in connections:
            pid    = conn.pid
            status = conn.status or "NONE"
            laddr  = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—"
            raddr  = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "—"
            rip    = conn.raddr.ip   if conn.raddr else None
            rport  = conn.raddr.port if conn.raddr else None

            try:
                proc = psutil.Process(pid) if pid else None
                name = proc.name() if proc else "system"
                exe  = proc.exe()  if proc else "—"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = "unknown"
                exe  = "—"

            is_suspicious = bool(rport and rport in SUSPICIOUS_PORTS)

            rows.append({
                "pid":           pid or "—",
                "name":          name,
                "status":        status,
                "local":         laddr,
                "remote":        raddr,
                "remote_ip":     rip,
                "remote_port":   rport,
                "is_suspicious": is_suspicious,
                "exe":           exe,
            })

        return rows

    def build_table(self, rows) -> Table:
        table = Table(
            title=f"Active Connections  [{datetime.datetime.now().strftime('%H:%M:%S')}]",
            border_style="purple",
            show_lines=False,
            box=box.SIMPLE_HEAD,
        )
        table.add_column("PID",            width=7,  style="dim")
        table.add_column("Process",        width=20, style="cyan")
        table.add_column("Status",         width=14)
        table.add_column("Local address",  width=26)
        table.add_column("Remote address", width=26)
        table.add_column("Flag",           width=12)

        for r in rows:
            color = STATUS_COLOR.get(r["status"], "white")
            flag  = "[bold red]SUSPICIOUS[/bold red]" if r["is_suspicious"] else ""
            table.add_row(
                str(r["pid"]),
                r["name"],
                f"[{color}]{r['status']}[/{color}]",
                r["local"],
                r["remote"],
                flag,
            )

        return table

    def build_summary(self, rows) -> str:
        total       = len(rows)
        established = sum(1 for r in rows if r["status"] == "ESTABLISHED")
        listening   = sum(1 for r in rows if r["status"] == "LISTEN")
        suspicious  = sum(1 for r in rows if r["is_suspicious"])

        parts = [
            f"[dim]Total: {total}[/dim]",
            f"[green]Established: {established}[/green]",
            f"[cyan]Listening: {listening}[/cyan]",
        ]
        if suspicious:
            parts.append(f"[bold red]Suspicious: {suspicious}[/bold red]")

        return "  |  ".join(parts)

    def run(self, live_mode=False):
        if live_mode:
            console.print("[dim]Live mode — press Ctrl+C to stop[/dim]\n")
            try:
                with Live(refresh_per_second=1, console=console) as live:
                    while True:
                        rows  = self.snapshot()
                        table = self.build_table(rows)
                        live.update(table)
                        time.sleep(2)
            except KeyboardInterrupt:
                console.print("[dim]Stopped.[/dim]")
        else:
            rows = self.snapshot()
            console.print(self.build_table(rows))
            console.print(self.build_summary(rows))

            suspicious = [r for r in rows if r["is_suspicious"]]
            if suspicious:
                console.print(
                    f"\n[bold red]⚠  {len(suspicious)} suspicious connection(s) detected![/bold red]"
                )
                for r in suspicious:
                    console.print(
                        f"  [red]{r['name']} (PID {r['pid']})[/red] → {r['remote']}"
                    )
            else:
                console.print("\n[green]No suspicious connections detected.[/green]")
