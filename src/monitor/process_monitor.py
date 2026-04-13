import psutil
import socket
import datetime
from rich.console import Console
from rich.table import Table
from rich.live import Live
import time

console = Console()

SUSPICIOUS_PORTS = {4444, 1337, 31337, 5555, 6666, 7777, 9999}

PROTO_MAP = {
    socket.AF_INET:  "IPv4",
    socket.AF_INET6: "IPv6",
}

STATUS_COLOR = {
    "ESTABLISHED": "green",
    "LISTEN":      "cyan",
    "TIME_WAIT":   "yellow",
    "CLOSE_WAIT":  "yellow",
    "SYN_SENT":    "red",
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
            pid = conn.pid
            status = conn.status
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "—"
            rport = conn.raddr.port if conn.raddr else None

            try:
                proc = psutil.Process(pid) if pid else None
                name = proc.name() if proc else "system"
                exe  = proc.exe()  if proc else "—"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = "unknown"
                exe  = "—"

            is_suspicious = rport in SUSPICIOUS_PORTS if rport else False

            rows.append({
                "pid":          pid or "—",
                "name":         name,
                "status":       status,
                "local":        laddr,
                "remote":       raddr,
                "is_suspicious": is_suspicious,
                "exe":          exe,
            })

        return rows

    def build_table(self, rows) -> Table:
        table = Table(
            title=f"Active Connections  [{datetime.datetime.now().strftime('%H:%M:%S')}]",
            border_style="purple",
            show_lines=False
        )
        table.add_column("PID",     width=7,  style="dim")
        table.add_column("Process", width=18, style="cyan")
        table.add_column("Status",  width=14)
        table.add_column("Local address",  width=24)
        table.add_column("Remote address", width=24)
        table.add_column("Flag",    width=12)

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

    def run(self, live_mode=False):
        if live_mode:
            with Live(refresh_per_second=2) as live:
                console.print("[dim]Live mode — press Ctrl+C to stop[/dim]")
                try:
                    while True:
                        rows = self.snapshot()
                        live.update(self.build_table(rows))
                        time.sleep(2)
                except KeyboardInterrupt:
                    pass
        else:
            rows = self.snapshot()
            console.print(self.build_table(rows))

            suspicious = [r for r in rows if r["is_suspicious"]]
            if suspicious:
                console.print(f"\n[bold red]⚠  {len(suspicious)} suspicious connection(s) detected![/bold red]")
                for r in suspicious:
                    console.print(f"  [red]{r['name']} (PID {r['pid']})[/red] → {r['remote']}")