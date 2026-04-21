"""
Command-line interface for Network Traffic Monitor
Run: python network_monitor_cli.py [options]
"""

import argparse
import sys
import os
from typing import Optional

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from monitor.network_monitor import NetworkMonitor
from monitor.network_monitor_ui import NetworkMonitorUI


class NetworkMonitorCLI:
    """Command-line interface for network monitor"""
    
    def __init__(self):
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description='🔍 Live Network Traffic Monitor - Capture packets and detect data exfiltration',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python network_monitor_cli.py live              # Live dashboard
  python network_monitor_cli.py monitor --duration 30  # Monitor for 30 seconds
  python network_monitor_cli.py stats             # Show statistics
  python network_monitor_cli.py alerts            # Show recent alerts
  python network_monitor_cli.py process --pid 1234  # Show process details

Note: Requires administrator/root privileges for packet capture
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Command to run')
        
        # Live dashboard command
        live_parser = subparsers.add_parser('live', help='Display live monitoring dashboard')
        live_parser.add_argument(
            '--interface', '-i',
            help='Network interface to monitor (e.g., eth0, wlan0)',
            default=None
        )
        live_parser.add_argument(
            '--refresh', '-r',
            type=int,
            help='Refresh interval in seconds (default: 2)',
            default=2
        )
        
        # Monitor command
        monitor_parser = subparsers.add_parser('monitor', help='Monitor for specified duration')
        monitor_parser.add_argument(
            '--duration', '-d',
            type=int,
            help='Duration to monitor in seconds (default: 30)',
            default=30
        )
        monitor_parser.add_argument(
            '--interface', '-i',
            help='Network interface to monitor',
            default=None
        )
        
        # Stats command
        stats_parser = subparsers.add_parser('stats', help='Show monitoring statistics')
        
        # Alerts command
        alerts_parser = subparsers.add_parser('alerts', help='Show recent alerts')
        alerts_parser.add_argument(
            '--limit', '-l',
            type=int,
            help='Number of alerts to display (default: 50)',
            default=50
        )
        
        # Process details command
        process_parser = subparsers.add_parser('process', help='Show process details')
        process_parser.add_argument(
            '--pid', '-p',
            type=int,
            help='Process ID to analyze',
            required=True
        )
        
        # Info command
        info_parser = subparsers.add_parser('info', help='Show information about the monitor')
        
        return parser
    
    def run(self, args: Optional[list] = None):
        """Run the CLI"""
        parsed_args = self.parser.parse_args(args)
        
        if not parsed_args.command:
            self.parser.print_help()
            return
        
        try:
            if parsed_args.command == 'live':
                self._run_live(parsed_args)
            elif parsed_args.command == 'monitor':
                self._run_monitor(parsed_args)
            elif parsed_args.command == 'stats':
                self._run_stats(parsed_args)
            elif parsed_args.command == 'alerts':
                self._run_alerts(parsed_args)
            elif parsed_args.command == 'process':
                self._run_process(parsed_args)
            elif parsed_args.command == 'info':
                self._run_info()
        except KeyboardInterrupt:
            print("\n\n✅ Monitor stopped by user")
        except PermissionError:
            print("❌ Error: Packet capture requires administrator/root privileges")
            print("   On Linux: sudo python network_monitor_cli.py ...")
            print("   On Windows: Run as Administrator")
        except Exception as e:
            print(f"❌ Error: {e}")
            sys.exit(1)
    
    def _run_live(self, args) -> None:
        """Run live monitoring dashboard"""
        print("""
╔═══════════════════════════════════════════════════════════════╗
║          🔍 LIVE NETWORK TRAFFIC MONITOR                      ║
║          Capture packets • Detect exfiltration                ║
║          Press Ctrl+C to exit                                 ║
╚═══════════════════════════════════════════════════════════════╝
        """)
        
        monitor = NetworkMonitor(interface=args.interface, update_interval=args.refresh)
        ui = NetworkMonitorUI(monitor, refresh_interval=args.refresh)
        
        ui.display_live()
    
    def _run_monitor(self, args) -> None:
        """Run monitoring for specified duration"""
        print(f"""
╔═══════════════════════════════════════════════════════════════╗
║          📊 MONITORING FOR {args.duration} SECONDS
║          Capturing packets and analyzing bandwidth...          ║
╚═══════════════════════════════════════════════════════════════╝
        """)
        
        monitor = NetworkMonitor(interface=args.interface)
        ui = NetworkMonitorUI(monitor)
        
        ui.display_simple(duration=args.duration)
        
        print("\n" + "="*60)
        print("📋 FINAL REPORT")
        print("="*60)
        
        stats = monitor.get_live_stats()
        print(f"\n✅ Monitoring Complete!")
        print(f"   Duration: {ui._format_uptime(stats['uptime'])}")
        print(f"   Packets Captured: {stats['packet_count']:,}")
        print(f"   Processes Monitored: {stats['total_processes_monitored']}")
        print(f"   Total Alerts: {len(monitor.bandwidth_analyzer.alerts)}")
    
    def _run_stats(self, args) -> None:
        """Display statistics"""
        print("""
╔═══════════════════════════════════════════════════════════════╗
║          📈 MONITOR STATISTICS                                ║
╚═══════════════════════════════════════════════════════════════╝
        """)
        
        monitor = NetworkMonitor()
        ui = NetworkMonitorUI(monitor)
        
        # Start monitoring briefly to get stats
        monitor.start()
        import time
        time.sleep(5)
        monitor.stop()
        
        ui.console.print(ui._create_stats_panel())
        ui.console.print("\n" + ui._create_bandwidth_table())
    
    def _run_alerts(self, args) -> None:
        """Display recent alerts"""
        print("""
╔═══════════════════════════════════════════════════════════════╗
║          ⚠️  ALERT REPORT                                      ║
╚═══════════════════════════════════════════════════════════════╝
        """)
        
        monitor = NetworkMonitor()
        ui = NetworkMonitorUI(monitor)
        
        # Start monitoring to gather alerts
        monitor.start()
        import time
        time.sleep(10)  # Monitor for 10 seconds to gather alerts
        monitor.stop()
        
        ui.display_alerts_report()
    
    def _run_process(self, args) -> None:
        """Display process details"""
        print(f"""
╔═══════════════════════════════════════════════════════════════╗
║          🔗 PROCESS DETAILS - PID {args.pid}
╚═══════════════════════════════════════════════════════════════╝
        """)
        
        monitor = NetworkMonitor()
        ui = NetworkMonitorUI(monitor)
        
        # Start monitoring to get process data
        monitor.start()
        import time
        time.sleep(5)
        monitor.stop()
        
        ui.display_process_details(args.pid)
    
    def _run_info(self) -> None:
        """Display information about the monitor"""
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        
        console = Console()
        
        console.print(Panel(
            "[bold cyan]🔍 NETWORK TRAFFIC MONITOR[/bold cyan]\n"
            "[dim]Live packet capture and bandwidth analysis with anomaly detection[/dim]",
            style="cyan"
        ))
        
        console.print("\n[bold yellow]Features:[/bold yellow]")
        features = [
            "✅ Real-time packet capture using Scapy",
            "✅ Per-process bandwidth tracking",
            "✅ Anomaly detection (spikes, exfiltration, suspicious ports)",
            "✅ Connection and port tracking",
            "✅ Historical bandwidth analysis",
            "✅ Rich live dashboard",
            "✅ Statistical analysis",
            "✅ Alert system with severity levels",
        ]
        
        for feature in features:
            console.print(f"  {feature}")
        
        console.print("\n[bold yellow]Detection Capabilities:[/bold yellow]")
        
        table = Table(title="Anomaly Detection", show_header=True, header_style="bold magenta")
        table.add_column("Type", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Threshold", style="yellow")
        
        table.add_row(
            "Spike",
            "Sudden increase in bandwidth",
            "2.5x baseline"
        )
        table.add_row(
            "High Bandwidth",
            "Sustained high data transfer",
            "> 100 MB/s"
        )
        table.add_row(
            "Exfiltration",
            "Potential data theft",
            "> 50 MB/s"
        )
        table.add_row(
            "Suspicious Ports",
            "Known backdoor/exploit ports",
            "31337, 5555, 6666, etc"
        )
        
        console.print(table)
        
        console.print("\n[bold yellow]Requirements:[/bold yellow]")
        console.print("  • Administrator/root privileges for packet capture")
        console.print("  • Python 3.8+")
        console.print("  • Scapy library")
        console.print("  • psutil library")
        console.print("  • Rich library for UI")
        
        console.print("\n[bold yellow]Performance:[/bold yellow]")
        console.print("  • Handles 1000+ processes efficiently")
        console.print("  • Real-time analysis with < 100ms latency")
        console.print("  • Minimal CPU/memory overhead")


def main():
    """Main entry point"""
    cli = NetworkMonitorCLI()
    cli.run()


if __name__ == '__main__':
    main()
