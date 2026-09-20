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


def manage_history(db):
    while True:
        console.print("\n[bold purple]📜  Veilguard History & Incident Viewer[/bold purple]")
        console.print("  [cyan]1[/cyan] — Port scan history")
        console.print("  [cyan]2[/cyan] — Visited website queries")
        console.print("  [cyan]3[/cyan] — Malicious website alerts")
        console.print("  [cyan]4[/cyan] — Multi-Agent correlated security incidents")
        console.print("  [cyan]b[/cyan] — Back to main menu")

        sub = input("\n> ").strip().lower()
        if sub == "1":
            db.show_history()
        elif sub == "2":
            visits = db.get_website_visits(limit=30)
            if not visits:
                console.print("[dim]No website visits recorded yet.[/dim]")
            else:
                table = Table(title="Recent Website Visits", border_style="cyan")
                table.add_column("Time", style="dim", width=19)
                table.add_column("Domain", style="white")
                table.add_column("Process", style="cyan")
                table.add_column("PID", style="dim", width=7)
                table.add_column("Status", width=12)
                for v in visits:
                    status = "[bold red]BLOCKED[/bold red]" if v["is_blocked"] else "[green]Allowed[/green]"
                    table.add_row(v["timestamp"][:19], v["domain"], v["process_name"] or "—", str(v["pid"] or "—"), status)
                console.print(table)
        elif sub == "3":
            alerts = db.get_website_alerts(limit=30)
            if not alerts:
                console.print("[dim]No website security alerts logged yet.[/dim]")
            else:
                table = Table(title="Website Security Alerts", border_style="red")
                table.add_column("Time", style="dim", width=19)
                table.add_column("Domain", style="red")
                table.add_column("Threat", style="yellow")
                table.add_column("Process", style="cyan")
                table.add_column("PID", style="dim", width=7)
                for a in alerts:
                    table.add_row(a["alert_time"][:19], a["domain"], f"{a['threat_type']} ({a['threat_level']})", a["process_name"] or "—", str(a["pid"] or "—"))
                console.print(table)
        elif sub == "4":
            incidents = db.get_incidents(limit=30)
            if not incidents:
                console.print("[green]✅ No correlated security incidents on record.[/green]")
            else:
                table = Table(title="Correlated Multi-Agent Security Incidents", border_style="red")
                table.add_column("ID", width=5, style="dim")
                table.add_column("Time", width=19, style="dim")
                table.add_column("Severity", width=10)
                table.add_column("Risk", width=8)
                table.add_column("Process", style="cyan")
                table.add_column("Event / Summary", style="white")
                table.add_column("Action Taken", style="bold yellow")
                for inc in incidents:
                    s_color = "red" if inc["severity"] in ("CRITICAL", "HIGH") else "yellow"
                    table.add_row(
                        str(inc["id"]),
                        inc["timestamp"][:19],
                        f"[{s_color}]{inc['severity']}[/{s_color}]",
                        f"{inc['risk_score']}/100",
                        f"{inc['process_name']} ({inc['pid'] or '—'})",
                        inc["summary"][:50] + ("..." if len(inc["summary"]) > 50 else ""),
                        inc["action_taken"]
                    )
                console.print(table)
        elif sub == "b":
            break


def manage_security_coordinator(db):
    try:
        from src.coordinator.security_coordinator import security_coordinator
        from src.monitor.process_hasher import process_hasher
    except ImportError:
        from coordinator.security_coordinator import security_coordinator
        from monitor.process_hasher import process_hasher

    while True:
        console.print("\n[bold purple]🤖  Multi-Agent Security Coordinator & Process Defense[/bold purple]")
        console.print("  [cyan]1[/cyan] — Network Process Audit & Binary Hashing (Audit all active sockets)")
        console.print("  [cyan]2[/cyan] — Inspect Specific Process (PID or Name forensics & VirusTotal)")
        console.print("  [cyan]3[/cyan] — Live Multi-Agent Guard (Real-time network + DNS + process defense)")
        console.print("  [cyan]4[/cyan] — View Correlated Incident Log")
        console.print("  [cyan]5[/cyan] — Terminate / Kill Rogue Process (Protected safe kill)")
        console.print("  [cyan]b[/cyan] — Back to main menu")

        sub = input("\n> ").strip().lower()
        if sub == "1":
            security_coordinator.audit_network_processes()
        elif sub == "2":
            target = input("Enter PID or process name (e.g. 1234 or python.exe): ").strip()
            if target:
                security_coordinator.inspect_process(target)
        elif sub == "3":
            try:
                console.print("\n[bold cyan]🛡️ Starting Live Multi-Agent Guard Mode...[/bold cyan]")
                console.print("[dim]Coordinating Packet Flow, DNS Sniffing, and Process Forensics.[/dim]")
                console.print("[dim]Press Ctrl+C to stop guard mode[/dim]\n")

                security_coordinator.start()

                # Start DNS capture
                dns_capture = DNSCapture()
                dns_capture.start_capture()

                # Start Network monitor
                net_monitor = NetworkMonitor()
                net_monitor.start()

                console.print("[green]✔ Multi-Agent Guard Active: Monitoring threats & exfiltration...[/green]")
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                console.print("\n[yellow]Stopping Multi-Agent Guard...[/yellow]")
                security_coordinator.stop()
                dns_capture.stop_capture()
                net_monitor.stop()
                console.print("[dim]Guard stopped.[/dim]")
            except Exception as e:
                console.print(f"[red]Guard error: {e}[/red]")
        elif sub == "4":
            incidents = db.get_incidents(limit=25)
            if not incidents:
                console.print("[green]✅ No security incidents recorded yet.[/green]")
            else:
                table = Table(title="Correlated Security Incidents", border_style="red")
                table.add_column("ID", width=5, style="dim")
                table.add_column("Severity", width=10)
                table.add_column("Risk", width=8)
                table.add_column("Process", style="cyan")
                table.add_column("SHA-256 (Truncated)", style="dim")
                table.add_column("Summary", style="white")
                table.add_column("Action Taken", style="bold yellow")
                for inc in incidents:
                    s_color = "red" if inc["severity"] in ("CRITICAL", "HIGH") else "yellow"
                    table.add_row(
                        str(inc["id"]),
                        f"[{s_color}]{inc['severity']}[/{s_color}]",
                        f"{inc['risk_score']}/100",
                        f"{inc['process_name']} ({inc['pid'] or '—'})",
                        (inc["sha256"][:12] + "...") if inc["sha256"] else "—",
                        inc["summary"][:45] + ("..." if len(inc["summary"]) > 45 else ""),
                        inc["action_taken"]
                    )
                console.print(table)
        elif sub == "5":
            target = input("Enter PID to terminate: ").strip()
            if target.isdigit():
                pid = int(target)
                confirm = input(f"Are you sure you want to terminate PID {pid}? (y/N): ").strip().lower()
                if confirm == "y":
                    ok, msg = process_hasher.terminate_process(pid)
                    if ok:
                        console.print(f"[green]✔ {msg}[/green]")
                    else:
                        console.print(f"[red]❌ {msg}[/red]")
        elif sub == "b":
            break


def manage_game_optimizer():
    """Interactive CLI menu for Game Optimizer & System Boost."""
    try:
        from src.optimizer.game_optimizer import game_optimizer
    except ImportError:
        from optimizer.game_optimizer import game_optimizer

    while True:
        status = game_optimizer.get_status()
        boost_badge = "[bold green]ACTIVE (Ultimate Performance)[/bold green]" if status.get("is_boosted") else "[bold yellow]INACTIVE (Standard Mode)[/bold yellow]"
        games = status.get("active_games", [])
        game_text = ", ".join([g["title"] for g in games]) if games else "[dim]No active game detected[/dim]"

        console.print("\n[bold cyan]🎮 Veilguard Game Optimizer & System Booster[/bold cyan]")
        console.print(f"Status: {boost_badge} | Power Plan: [bold cyan]{status.get('power_plan', 'Standard')}[/bold cyan]")
        ram_info = status.get("ram", {})
        console.print(f"CPU Load: [bold yellow]{status.get('cpu_percent', 0)}%[/bold yellow] | RAM: [bold cyan]{ram_info.get('used_mb', 0)} MB[/bold cyan] / {ram_info.get('total_mb', 0)} MB ([bold]{ram_info.get('percent', 0)}%[/bold]) | Free: [bold green]{status.get('ram_free_gb', 0)} GB[/bold green]")
        console.print(f"Active Games: {game_text}")
        if status.get("memory_freed_total_mb", 0) > 0:
            console.print(f"[dim]Total RAM Freed This Session: {status['memory_freed_total_mb']} MB[/dim]")

        console.print("\n  [cyan]1[/cyan] — " + ("Restore Normal Mode (Standard Power & Notifications)" if status.get("is_boosted") else "Engage 1-Click Ultra Game Boost (Power Plan + RAM + DNS Flush)"))
        console.print("  [cyan]2[/cyan] — Deep Working-Set RAM Purge (Flush standby RAM cache)")
        console.print("  [cyan]3[/cyan] — Flush Low-Latency DNS Cache (Clear packet jitter)")
        console.print("  [cyan]4[/cyan] — View Memory-Heavy Background Bloatware")
        console.print("  [cyan]5[/cyan] — Terminate Background App by PID")
        console.print("  [cyan]b[/cyan] — Back to main menu")

        sub = input("\n> ").strip().lower()

        if sub == "1":
            if status.get("is_boosted"):
                with console.status("[dim]Restoring standard mode...[/dim]"):
                    res = game_optimizer.disable_boost()
                console.print(f"[green]✔ {res.get('message', 'Normal mode restored.')}[/green]")
            else:
                with console.status("[dim]Engaging Ultra Game Boost (Power Plan, RAM Purge, DNS Flush)...[/dim]"):
                    res = game_optimizer.enable_boost()
                console.print(f"[bold green]🚀 Ultra Game Boost Engaged![/bold green]")
                console.print(f"   • Power Plan: {'Switched to High/Ultimate Performance' if res.get('power_plan_switched') else 'Maintained'}")
                console.print(f"   • RAM Freed: [bold cyan]{res.get('ram_freed_mb', 0)} MB[/bold cyan]")
                console.print(f"   • DNS Cache: {'Flushed' if res.get('dns_flushed') else 'Skipped'}")
                console.print("   • Silent Gaming Mode: [bold green]ON[/bold green] (Background alerts muted)")

        elif sub == "2":
            with console.status("[dim]Purging RAM working set cache...[/dim]"):
                res = game_optimizer.clean_ram()
            console.print(f"[bold green]✔ RAM Cleanup Complete![/bold green]")
            console.print(f"   • Freed: [bold cyan]{res.get('freed_mb', 0)} MB[/bold cyan]")
            console.print(f"   • Processes Trimmed: {res.get('processes_trimmed', 0)}")
            console.print(f"   • Available RAM: {res.get('available_mb', 0)} MB ({res.get('ram_used_percent', 0)}% in use)")

        elif sub == "3":
            ok = game_optimizer.flush_dns()
            if ok:
                console.print("[bold green]✔ DNS cache flushed successfully. Network latency optimized.[/bold green]")
            else:
                console.print("[red]❌ Failed to flush DNS cache.[/red]")

        elif sub == "4":
            apps = game_optimizer.get_optimizable_apps(min_ram_mb=35.0)
            if not apps:
                console.print("[green]✔ No heavy background bloatware detected. System is running lean![/green]")
            else:
                table = Table(title=f"Optimizable Background Applications ({len(apps)} found)", box=box.ROUNDED)
                table.add_column("PID", style="dim", justify="right")
                table.add_column("Process Name", style="bold cyan")
                table.add_column("Memory (MB)", style="bold yellow", justify="right")
                table.add_column("CPU %", style="dim", justify="right")
                table.add_column("Safe to Close", style="green")

                for a in apps[:20]:
                    table.add_row(
                        str(a["pid"]),
                        a["name"],
                        f"{a['memory_mb']:.1f}",
                        f"{a.get('cpu_percent', 0.0):.1f}%",
                        "✔ Yes" if a.get("is_safe_to_kill") else "No"
                    )
                console.print(table)
                if len(apps) > 20:
                    console.print(f"[dim]Showing top 20 of {len(apps)} processes.[/dim]")

        elif sub == "5":
            target = input("Enter PID to terminate: ").strip()
            if target.isdigit():
                pid = int(target)
                confirm = input(f"Are you sure you want to close PID {pid}? (y/N): ").strip().lower()
                if confirm == "y":
                    res = game_optimizer.terminate_background_app(pid)
                    if res.get("success"):
                        console.print(f"[green]✔ {res.get('message', 'Process closed.')}[/green]")
                    else:
                        console.print(f"[red]❌ {res.get('error', 'Failed to terminate process.')}[/red]")

        elif sub == "b":
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
        console.print("\n[bold]Veilguard Security Modules (Select an Option):[/bold]")
        console.print("  [cyan]1[/cyan] — Scan Network Ports & Find Vulnerabilities (CVE Flaws)")
        console.print("  [cyan]2[/cyan] — Monitor Running Programs & Sockets (Live App Connections)")
        console.print("  [cyan]3[/cyan] — Network Speed & Bandwidth Meter (Packet Sniffer)")
        console.print("  [cyan]4[/cyan] — Web Shield: Block Malicious & Phishing Sites (DNS Sinkhole)")
        console.print("  [cyan]5[/cyan] — Activity Record Book (Scan, Web, & Security History)")
        console.print("  [cyan]6[/cyan] — Manage Blocked Websites (View Active Blocks / 1-Click Unblock)")
        console.print("  [cyan]7[/cyan] — Global Threat Intelligence (Abuse.ch Feeds & VirusTotal Cloud)")
        console.print("  [cyan]8[/cyan] — Multi-Agent Defense & App Forensics (Digital Fingerprints / Hashes)")
        console.print("  [cyan]9[/cyan] — Game Optimizer & System Boost (RAM Purge, Power Plan & Low-Latency)")
        console.print("  [cyan]10[/cyan] — Launch Cyber Operations Dashboard (Browser UI)")
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
            manage_history(db)

        elif choice == "6":
            manage_blocked_websites(db)

        elif choice == "7":
            manage_threat_intelligence(db)

        elif choice == "8":
            manage_security_coordinator(db)

        elif choice == "9":
            manage_game_optimizer()

        elif choice == "10":
            try:
                from src.web.server import start_web_server
                start_web_server(port=8000, open_browser=True)
            except Exception as e:
                console.print(f"[red]❌ Web server error: {e}[/red]")

        elif choice == "q":
            console.print("[dim]Goodbye.[/dim]")
            break

        else:
            console.print("[red]Invalid choice.[/red]")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--web", "-w"):
        from src.web.server import start_web_server
        start_web_server(port=8000, open_browser=True)
    else:
        main()