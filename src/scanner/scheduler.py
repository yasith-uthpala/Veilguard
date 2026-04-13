import schedule
import time
import json
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box
from src.scanner.port_scanner import PortScanner
from src.db.database import Database

console = Console()


class ScheduledScanner:
    """Manage scheduled port scans and detect changes"""
    
    def __init__(self, target: str):
        self.target = target
        self.db = Database()
        self.db.init()
        self.scan_history = {}
        self.load_history()
    
    def load_history(self):
        """Load scan history from database"""
        try:
            with self.db.connect() as conn:
                rows = conn.execute("""
                    SELECT port, service, product, is_vulnerable, scanned_at 
                    FROM scans 
                    WHERE target = ? 
                    ORDER BY scanned_at DESC
                """, (self.target,)).fetchall()
                
                # Group by scan time to get snapshots
                for row in rows:
                    port = row[0]
                    if port not in self.scan_history:
                        self.scan_history[port] = {
                            "service": row[1],
                            "product": row[2],
                            "is_vulnerable": row[3],
                            "last_scan": row[4]
                        }
        except Exception as e:
            console.print(f"[dim]Could not load history: {e}[/dim]")
    
    def detect_changes(self, new_results: list) -> dict:
        """
        Compare new scan results with previous scan.
        Returns dict with:
        - new_ports: ports that weren't open before
        - closed_ports: ports that were open but are now closed
        - version_changes: ports where service/product version changed
        - vulnerability_changes: ports where vulnerability status changed
        """
        changes = {
            "new_ports": [],
            "closed_ports": [],
            "version_changes": [],
            "vulnerability_changes": []
        }
        
        # Get current open ports
        current_ports = {r["port"]: r for r in new_results}
        previous_ports = set(self.scan_history.keys())
        current_port_set = set(current_ports.keys())
        
        # Find new ports
        new_ports = current_port_set - previous_ports
        for port in new_ports:
            result = current_ports[port]
            changes["new_ports"].append({
                "port": port,
                "service": result.get("service"),
                "product": result.get("product"),
                "risk": result.get("risk")
            })
        
        # Find closed ports
        closed_ports = previous_ports - current_port_set
        for port in closed_ports:
            changes["closed_ports"].append({
                "port": port,
                "service": self.scan_history[port]["service"],
                "product": self.scan_history[port]["product"]
            })
        
        # Find version changes and vulnerability changes
        for port in current_port_set & previous_ports:
            new_result = current_ports[port]
            old_data = self.scan_history[port]
            
            # Check for version/product changes
            if (new_result.get("product") != old_data["product"] or 
                new_result.get("service") != old_data["service"]):
                changes["version_changes"].append({
                    "port": port,
                    "service": new_result.get("service"),
                    "old_product": old_data["product"],
                    "new_product": new_result.get("product")
                })
            
            # Check for vulnerability status changes
            if new_result.get("is_vulnerable") != old_data["is_vulnerable"]:
                changes["vulnerability_changes"].append({
                    "port": port,
                    "service": new_result.get("service"),
                    "now_vulnerable": new_result.get("is_vulnerable")
                })
        
        return changes
    
    def display_changes(self, changes: dict):
        """Display detected changes to console"""
        if not any(changes.values()):
            console.print("[green]✅ No changes detected - all ports stable[/green]")
            return
        
        console.print("\n[bold yellow]⚠️  CHANGES DETECTED[/bold yellow]\n")
        
        if changes["new_ports"]:
            console.print("[bold red]🔴 NEW PORTS DETECTED:[/bold red]")
            table = Table(box=box.SIMPLE)
            table.add_column("Port", style="cyan")
            table.add_column("Service")
            table.add_column("Product")
            table.add_column("Risk", style="red")
            
            for port_data in changes["new_ports"]:
                table.add_row(
                    str(port_data["port"]),
                    port_data.get("service", "unknown"),
                    port_data.get("product", ""),
                    port_data.get("risk", "UNKNOWN")
                )
            console.print(table)
            console.print()
        
        if changes["closed_ports"]:
            console.print("[bold green]✅ PORTS CLOSED:[/bold green]")
            table = Table(box=box.SIMPLE)
            table.add_column("Port", style="cyan")
            table.add_column("Service")
            table.add_column("Product")
            
            for port_data in changes["closed_ports"]:
                table.add_row(
                    str(port_data["port"]),
                    port_data.get("service", "unknown"),
                    port_data.get("product", "")
                )
            console.print(table)
            console.print()
        
        if changes["version_changes"]:
            console.print("[bold yellow]⚙️  VERSION CHANGES:[/bold yellow]")
            table = Table(box=box.SIMPLE)
            table.add_column("Port", style="cyan")
            table.add_column("Service")
            table.add_column("Old Product")
            table.add_column("New Product", style="yellow")
            
            for change in changes["version_changes"]:
                table.add_row(
                    str(change["port"]),
                    change.get("service", "unknown"),
                    change.get("old_product", ""),
                    change.get("new_product", "")
                )
            console.print(table)
            console.print()
        
        if changes["vulnerability_changes"]:
            console.print("[bold orange]🔓 VULNERABILITY CHANGES:[/bold orange]")
            table = Table(box=box.SIMPLE)
            table.add_column("Port", style="cyan")
            table.add_column("Service")
            table.add_column("Status")
            
            for change in changes["vulnerability_changes"]:
                status = "[red]NOW VULNERABLE[/red]" if change["now_vulnerable"] else "[green]PATCHED[/green]"
                table.add_row(
                    str(change["port"]),
                    change.get("service", "unknown"),
                    status
                )
            console.print(table)
            console.print()
    
    def schedule_daily_scan(self, time_str: str = "02:00"):
        """Schedule daily scans at specified time (24-hour format, e.g. "02:00")"""
        schedule.every().day.at(time_str).do(self.run_scheduled_scan)
        console.print(f"[green]✅ Daily scan scheduled at {time_str}[/green]")
    
    def schedule_weekly_scan(self, day: str = "monday", time_str: str = "02:00"):
        """Schedule weekly scans (day: 'monday', 'tuesday', etc.)"""
        getattr(schedule.every(), day).at(time_str).do(self.run_scheduled_scan)
        console.print(f"[green]✅ Weekly scan scheduled for {day.capitalize()} at {time_str}[/green]")
    
    def schedule_interval_scan(self, hours: int = 24):
        """Schedule scans at regular intervals"""
        schedule.every(hours).hours.do(self.run_scheduled_scan)
        console.print(f"[green]✅ Scan scheduled every {hours} hours[/green]")
    
    def run_scheduled_scan(self):
        """Execute a scheduled scan"""
        console.print(f"\n[bold cyan]🔄 Scheduled scan started: {self.target}[/bold cyan]")
        console.print(f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")
        
        try:
            scanner = PortScanner(self.target, self.db)
            # Run quick scan automatically
            results = scanner.scan(port_range="1-1024")
            
            if results:
                # Detect changes
                changes = self.detect_changes(results)
                self.display_changes(changes)
                
                # Save to database
                self.db.save_scan(results)
                
                # Update history
                for r in results:
                    self.scan_history[r["port"]] = {
                        "service": r.get("service"),
                        "product": r.get("product"),
                        "is_vulnerable": r.get("is_vulnerable"),
                        "last_scan": datetime.now().isoformat()
                    }
                
                console.print(f"\n[green]✅ Scan completed and results saved[/green]")
            else:
                console.print("[yellow]No ports found[/yellow]")
                
        except Exception as e:
            console.print(f"[red]❌ Scan error: {e}[/red]")
    
    def start_scheduler(self):
        """Start the scheduler and keep it running"""
        console.print("[bold cyan]Scheduler started - press Ctrl+C to stop[/bold cyan]\n")
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            console.print("\n[yellow]Scheduler stopped[/yellow]")
    
    def get_pending_jobs(self) -> list:
        """Get list of pending scheduled jobs"""
        return schedule.get_jobs()
    
    def clear_schedule(self):
        """Clear all scheduled jobs"""
        schedule.clear()
        console.print("[yellow]All scheduled jobs cleared[/yellow]")
