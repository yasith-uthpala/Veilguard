import os
import sys
from dotenv import load_dotenv

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Load environment variables from .env
load_dotenv()

from src.scanner.port_scanner import PortScanner
from src.monitor.process_monitor import ProcessMonitor
from src.monitor.network_monitor import NetworkMonitor
from src.monitor.network_monitor_ui import NetworkMonitorUI
from src.monitor.website_monitor import DNSCapture
from src.monitor.website_monitor_ui import WebsiteMonitorUI
from src.db.database import Database
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import time

console = Console()

def manage_blocked_websites(db):
    try:
        from src.monitor.site_blocker import site_blocker
    except ImportError:
        from monitor.site_blocker import site_blocker

    while True:
        console.print("\n[bold purple]🛡️  Manage Blocked Websites[/bold purple]")
        blocks = site_blocker.get_active_blocks()
        console.print(f"Active system-level blocks: [bold cyan]{len(blocks)}[/bold cyan]")
        console.print("  [cyan]1[/cyan] — List all blocked domains")
        console.print("  [cyan]2[/cyan] — Unblock a specific domain")
        console.print("  [cyan]3[/cyan] — Unblock ALL domains (Emergency reset)")
        console.print("  [cyan]4[/cyan] — Manually block a domain")
        console.print("  [cyan]b[/cyan] — Back to main menu")

        sub_choice = input("\n> ").strip().lower()
        if sub_choice == "1":
            if not blocks:
                console.print("[green]No websites are currently blocked.[/green]")
            else:
                table = Table(title="Currently Blocked Websites", border_style="red")
                table.add_column("#", width=5, style="dim")
                table.add_column("Domain", style="red")
                table.add_column("Enforcement", style="bold green")
                for idx, dom in enumerate(blocks, 1):
                    table.add_row(str(idx), dom, "0.0.0.0 Sinkhole + Firewall")
                console.print(table)

        elif sub_choice == "2":
            if not blocks:
                console.print("[yellow]No websites to unblock.[/yellow]")
                continue
            console.print("Enter domain to unblock (or list number):")
            target = input("> ").strip().lower()
            if not target:
                continue
            if target.isdigit():
                idx = int(target) - 1
                if 0 <= idx < len(blocks):
                    target = blocks[idx]

            success = site_blocker.unblock_domain(target)
            if success:
                db.remove_blocked_site(target)
                console.print(f"[bold green]✅ Successfully unblocked {target}! Network restored.[/bold green]")
            else:
                console.print(f"[yellow]Could not unblock '{target}'. Check if it was in the blocked list.[/yellow]")

        elif sub_choice == "3":
            confirm = input("Are you sure you want to unblock ALL websites? (y/N): ").strip().lower()
            if confirm == "y":
                count = site_blocker.unblock_all()
                db.clear_all_blocked_sites()
                console.print(f"[bold green]✅ Successfully unblocked {count} domain(s). System hosts file and firewall restored![/bold green]")

        elif sub_choice == "4":
            domain = input("Enter domain to block (e.g. example.com): ").strip()
            if domain:
                if site_blocker.block_domain(domain, reason="manual"):
                    db.save_blocked_site(domain, "manual", "high", "Manually blocked by user")
                    console.print(f"[bold red]🚫 {domain} is now actively blocked on your system![/bold red]")
                else:
                    console.print(f"[red]Failed to block {domain}. Run as Administrator.[/red]")

        elif sub_choice == "b":
            break


def manage_threat_intelligence(db):
    try:
        from src.scanner.threat_lookup import ThreatLookup, GeoIPLookup
        from src.monitor.threat_feed_sync import threat_feed_sync
    except ImportError:
        from scanner.threat_lookup import ThreatLookup, GeoIPLookup
        from monitor.threat_feed_sync import threat_feed_sync

    vt = ThreatLookup()
    geoip = GeoIPLookup()

    while True:
        stats = db.get_threat_stats()
        console.print("\n[bold purple]🌐 Threat Intelligence & Real-World Feeds[/bold purple]")
        console.print(f"Total Threat Indicators Indexed: [bold cyan]{stats.get('total_indicators', 0):,}[/bold cyan]")
        if stats.get("by_source"):
            sources_summary = ", ".join(f"{k}: {v:,}" for k, v in stats["by_source"].items())
            console.print(f"[dim]Sources: {sources_summary}[/dim]")
        if stats.get("cached_domains"):
            console.print(f"[dim]VirusTotal Cached Domains: {stats['cached_domains']:,}[/dim]")

        console.print("\n  [cyan]1[/cyan] — Sync / Update Threat Feeds now (URLhaus + ThreatFox)")
        console.print("  [cyan]2[/cyan] — Lookup Domain on VirusTotal (70+ security engines)")
        console.print("  [cyan]3[/cyan] — Lookup IP Address (VirusTotal & GeoIP)")
        console.print("  [cyan]b[/cyan] — Back to main menu")

        sub_choice = input("\n> ").strip().lower()

        if sub_choice == "1":
            threat_feed_sync.sync(force=True, verbose=True)

        elif sub_choice == "2":
            domain = input("Enter domain name (e.g. example.com): ").strip()
            if domain:
                console.print(f"[dim]Checking VirusTotal for {domain}...[/dim]")
                res = vt.lookup_domain(domain)
                if "error" in res:
                    console.print(f"[red]Error: {res['error']}[/red]")
                else:
                    v_color = "red" if res["verdict"] == "malicious" else "yellow" if res["verdict"] == "suspicious" else "green"
                    console.print(Panel(
                        f"[bold {v_color}]Verdict: {res['verdict_label']}[/bold {v_color}]\n"
                        f"Engines: [red]{res['malicious']} malicious[/red], "
                        f"[yellow]{res['suspicious']} suspicious[/yellow], "
                        f"[green]{res['harmless']} clean[/green] (out of {res['total_engines']})\n"
                        f"Reputation Score: {res['reputation']}\n"
                        f"Cached: {res['cached']}",
                        title=f"VirusTotal Report: {domain}",
                        border_style=v_color
                    ))

        elif sub_choice == "3":
            ip = input("Enter IP address: ").strip()
            if ip:
                console.print(f"[dim]Resolving GeoIP and VirusTotal for {ip}...[/dim]")
                geo = geoip.lookup(ip)
                if "error" not in geo:
                    console.print(f"[cyan]Location:[/cyan] {geo.get('flag','')} {geo.get('city','?')}, {geo.get('country','?')} (ISP: {geo.get('isp','?')})")
                vt_res = vt.lookup_ip(ip)
                if "error" not in vt_res:
                    v_color = "red" if vt_res["verdict"] == "malicious" else "yellow" if vt_res["verdict"] == "suspicious" else "green"
                    console.print(f"[{v_color}]VirusTotal Verdict: {vt_res['verdict_label']}[/{v_color}]")
                else:
                    console.print(f"[dim]VT: {vt_res.get('error')}[/dim]")

        elif sub_choice == "b":
            break


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
        console.print("  [cyan]6[/cyan] — Manage blocked websites (View / Unblock)")
        console.print("  [cyan]7[/cyan] — Threat Intelligence & Live Feeds (Abuse.ch / VirusTotal)")
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

        elif choice == "6":
            manage_blocked_websites(db)

        elif choice == "7":
            manage_threat_intelligence(db)

        elif choice == "q":
            console.print("[dim]Goodbye.[/dim]")
            break

        else:
            console.print("[red]Invalid choice.[/red]")

if __name__ == "__main__":
    main()