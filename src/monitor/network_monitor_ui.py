from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich import box
from datetime import datetime
import time

console = Console()

class NetworkMonitorUI:
    """Simple, reliable UI for network monitor"""
    
    def __init__(self, monitor):
        self.monitor = monitor
    
    def _build_ui(self):
        """Build the UI as a single renderable object"""
        stats = self.monitor.get_live_stats()
        
        # Header
        uptime_str = stats.get('uptime', 0)
        packet_count = stats.get('packet_count', 0)
        alert_count = len(stats.get('recent_alerts', []))
        process_count = stats.get('total_processes_monitored', 0)
        
        header = f"🔍 Network Monitor | Packets: {packet_count} | Processes: {process_count} | Alerts: {alert_count} | Uptime: {uptime_str:.0f}s"
        
        # Create a renderable group
        renderables = []
        renderables.append(Panel(header, style="bold cyan"))
        
        # Bandwidth table
        if stats.get('top_processes'):
            table = Table(title="📊 Top Processes by Bandwidth", box=box.ROUNDED, border_style="green")
            table.add_column("PID", style="cyan", width=8)
            table.add_column("Process Name", style="yellow", width=25)
            table.add_column("Total", style="green", width=12)
            table.add_column("Upload", style="blue", width=12)
            table.add_column("Download", style="magenta", width=12)
            
            for name, pid, total_bytes in stats['top_processes'][:10]:
                total_mb = total_bytes / (1024 * 1024)
                upload_mb = total_mb * 0.5
                download_mb = total_mb * 0.5
                
                table.add_row(
                    str(pid),
                    name[:25],
                    f"{total_mb:.2f} MB",
                    f"{upload_mb:.2f} MB",
                    f"{download_mb:.2f} MB"
                )
            
            renderables.append(table)
        else:
            renderables.append(Panel("[yellow]⚠️  No processes detected. Try opening a browser or running: ping 8.8.8.8[/yellow]"))
        
        # Alerts
        if stats.get('recent_alerts'):
            alert_table = Table(title="🚨 Recent Alerts", box=box.ROUNDED, border_style="red")
            alert_table.add_column("Time", width=10)
            alert_table.add_column("Type", style="red", width=15)
            alert_table.add_column("Process", width=20)
            alert_table.add_column("Details", width=40)
            
            for alert in stats['recent_alerts'][-5:]:
                alert_time = alert.get('time', 'N/A') if isinstance(alert, dict) else getattr(alert, 'time', 'N/A')
                alert_type = alert.get('alert_type', 'UNKNOWN') if isinstance(alert, dict) else getattr(alert, 'alert_type', 'UNKNOWN')
                process_name = alert.get('process_name', 'N/A') if isinstance(alert, dict) else getattr(alert, 'process_name', 'N/A')
                details = alert.get('details', 'N/A') if isinstance(alert, dict) else getattr(alert, 'details', 'N/A')
                
                alert_table.add_row(
                    str(alert_time),
                    alert_type,
                    process_name,
                    str(details)[:40]
                )
            
            renderables.append(alert_table)
        else:
            renderables.append(Panel("[green]✅ No alerts[/green]"))
        
        # Statistics
        stat_text = f"""
📈 Statistics:
  • Total Processes: {process_count}
  • Total Packets: {packet_count}
  • Total Alerts: {alert_count}
  • Capture Duration: {uptime_str:.1f}s
        """
        renderables.append(Panel(stat_text, title="📊 Stats", border_style="blue"))
        
        renderables.append(Panel("[dim]Press Ctrl+C to exit[/dim]"))
        
        # Return as a vertical layout
        from rich.console import Group
        return Group(*renderables)
    
    def display_live(self, update_interval=2):
        """Display live network stats"""
        try:
            with Live(self._build_ui(), refresh_per_second=1/update_interval, console=console) as live:
                while True:
                    time.sleep(update_interval)
                    live.update(self._build_ui())
        except KeyboardInterrupt:
            console.print("\n[yellow]✋ Monitoring stopped[/yellow]")
    
    def display_summary(self):
        """Display summary report"""
        stats = self.monitor.get_live_stats()
        
        console.print("\n[bold cyan]═══ Network Monitor Summary ═══[/bold cyan]\n")
        
        console.print(f"📊 Packets captured: {stats['packet_count']}")
        console.print(f"🔍 Processes detected: {stats['total_processes_monitored']}")
        console.print(f"⏱️  Uptime: {stats['uptime']:.2f}s")
        console.print(f"🚨 Alerts: {len(stats['recent_alerts'])}\n")
        
        if stats['top_processes']:
            table = Table(title="Top Processes", box=box.ROUNDED)
            table.add_column("PID", style="cyan")
            table.add_column("Process", style="yellow")
            table.add_column("Bytes", style="green")
            
            for name, pid, total_bytes in stats['top_processes'][:10]:
                mb = total_bytes / (1024 * 1024)
                table.add_row(str(pid), name, f"{mb:.2f} MB")
            
            console.print(table)