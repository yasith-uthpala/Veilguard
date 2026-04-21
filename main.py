from src.scanner.port_scanner import PortScanner
from src.monitor.process_monitor import ProcessMonitor
from src.monitor.network_monitor import NetworkMonitor
from src.monitor.network_monitor_ui import NetworkMonitorUI
from src.monitor.website_monitor import DNSCapture
from src.monitor.website_monitor_ui import WebsiteMonitorUI
from src.db.database import Database
from rich.console import Console
from rich.panel import Panel
import time

console = Console()

def main():
    console.print(Panel.fit(
        "[bold purple]Veilguard Security Suite[/bold purple]\n"
        "[dim]Open-source endpoint protection[/dim]",
        border_style="purple"
    ))

    db = Database()
    db.init()  # ✅ CORRECT - Use init(), not init_db()

    while True:
        console.print("\n[bold]What do you want to do?[/bold]")
        console.print("  [cyan]1[/cyan] — Scan ports")
        console.print("  [cyan]2[/cyan] — Monitor processes")
        console.print("  [cyan]3[/cyan] — Monitor network traffic (Live)")
        console.print("  [cyan]4[/cyan] — Monitor websites & block malicious sites")
        console.print("  [cyan]5[/cyan] — View scan history")
        console.print("  [cyan]q[/cyan] — Quit")

        choice = input("\n> ").strip().lower()

        if choice == "1":
            target = input("Enter target IP or hostname: ").strip()
            scanner = PortScanner(target, db)
            scanner.run()

        elif choice == "2":
            monitor = ProcessMonitor()
            monitor.run()

        elif choice == "3":
            try:
                console.print("\n[cyan]Starting Network Traffic Monitor...[/cyan]")
                console.print("[dim]Press Ctrl+C to stop monitoring[/dim]\n")
                network_monitor = NetworkMonitor()
                ui = NetworkMonitorUI(network_monitor)
                network_monitor.start()
                ui.display_live(update_interval=2)
                network_monitor.stop()
            except PermissionError:
                console.print("[red]❌ Error: Run as Administrator/root for packet capture[/red]")
                console.print("   On Windows: Run PowerShell as Administrator")
                console.print("   On Linux/Mac: Use 'sudo python main.py'")
            except Exception as e:
                console.print(f"[red]❌ Error: {e}[/red]")
                import traceback
                traceback.print_exc()

        elif choice == "4":
            try:
                console.print("\n[cyan]🌐 Starting Website Monitor...[/cyan]")
                console.print("[dim]Press Ctrl+C to stop monitoring[/dim]")
                console.print("[yellow]Capturing DNS queries to detect malicious websites...[/yellow]\n")
                
                dns_capture = DNSCapture()
                dns_capture.start_capture()
                ui = WebsiteMonitorUI(dns_capture)
                
                time.sleep(1)  # Give capture thread time to start
                ui.display_live(update_interval=2)
                
                dns_capture.stop_capture()
            except PermissionError:
                console.print("[red]❌ Error: Run as Administrator/root for DNS capture[/red]")
                console.print("   On Windows: Run PowerShell as Administrator")
                console.print("   On Linux/Mac: Use 'sudo python main.py'")
            except Exception as e:
                console.print(f"[red]❌ Error: {e}[/red]")
                import traceback
                traceback.print_exc()

        elif choice == "5":
            db.show_history()

        elif choice == "q":
            console.print("[dim]Goodbye.[/dim]")
            break

        else:
            console.print("[red]Invalid choice.[/red]")

if __name__ == "__main__":
    main()