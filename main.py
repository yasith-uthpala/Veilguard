from src.scanner.port_scanner import PortScanner
from src.monitor.process_monitor import ProcessMonitor
from src.db.database import Database
from rich.console import Console
from rich.panel import Panel

console = Console()

def main():
    console.print(Panel.fit(
        "[bold purple]Veilguard Security Suite[/bold purple]\n"
        "[dim]Open-source endpoint protection[/dim]",
        border_style="purple"
    ))

    db = Database()
    db.init()

    while True:
        console.print("\n[bold]What do you want to do?[/bold]")
        console.print("  [cyan]1[/cyan] — Scan ports")
        console.print("  [cyan]2[/cyan] — Monitor processes")
        console.print("  [cyan]3[/cyan] — View scan history")
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
            db.show_history()

        elif choice == "q":
            console.print("[dim]Goodbye.[/dim]")
            break

        else:
            console.print("[red]Invalid choice.[/red]")

if __name__ == "__main__":
    main()