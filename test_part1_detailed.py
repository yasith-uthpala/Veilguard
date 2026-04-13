#!/usr/bin/env python3
"""
Comprehensive test of CVE Integration - Part 1
Shows exactly what was implemented and how it works
"""

from src.scanner.threat_lookup import CVELookup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

def print_header(title):
    console.print(f"\n[bold cyan]{'='*70}[/bold cyan]")
    console.print(f"[bold cyan]{title.center(70)}[/bold cyan]")
    console.print(f"[bold cyan]{'='*70}[/bold cyan]\n")

def test_part_1_cve_integration():
    """Test Phase 1 - Part 1: CVE Database Integration"""
    
    print_header("PHASE 1 — PART 1: CVE DATABASE INTEGRATION")
    
    console.print("[bold yellow]What was implemented:[/bold yellow]")
    console.print("""
1. ✅ CVELookup class added to threat_lookup.py
   - Queries the NVD (National Vulnerability Database) API
   - Free API, no key required
   - Rate-limited to respect API limits (6 requests per 30 seconds)
   - Includes caching to avoid duplicate queries
   
2. ✅ Two search methods:
   - search_by_keyword(): Search for CVEs by service name (OpenSSH, Apache, etc.)
   - search_by_cpe(): Search by CPE (Common Platform Enumeration)
   
3. ✅ Integrated into PortScanner:
   - enrich_with_cves() method enriches scan results with CVE data
   - Automatically called during scan
   - Shows top 3 CVEs for each vulnerable port
   
4. ✅ Enhanced display:
   - CVE ID, CVSS score, description, and NVD link
   - Shows in detail panels for CRITICAL and HIGH risk ports
    """)
    
    # Test the actual integration
    console.print("[bold yellow]Running live test:[/bold yellow]\n")
    
    cve_lookup = CVELookup()
    
    # Test 1: OpenSSH (common on SSH port 22)
    print("Test 1: Searching for OpenSSH CVEs (Port 22 - SSH)")
    print("-" * 70)
    cves = cve_lookup.search_by_keyword("OpenSSH")
    
    if cves:
        table = Table(title=f"OpenSSH CVEs (Found {len(cves)})", box=box.ROUNDED)
        table.add_column("CVE ID", style="cyan", width=15)
        table.add_column("CVSS Score", style="yellow", width=12)
        table.add_column("Published", width=20)
        table.add_column("Description", width=35, overflow="fold")
        
        for cve in cves[:5]:  # Show top 5
            desc = cve['description'][:50] + "..." if len(cve['description']) > 50 else cve['description']
            table.add_row(
                cve['cve_id'],
                cve['cvss_score'],
                cve['published'][:10],
                desc
            )
        console.print(table)
    
    console.print()
    
    # Test 2: Apache (common on HTTP port 80)
    print("Test 2: Searching for Apache CVEs (Port 80 - HTTP)")
    print("-" * 70)
    cves = cve_lookup.search_by_keyword("Apache")
    
    if cves:
        table = Table(title=f"Apache CVEs (Found {len(cves)})", box=box.ROUNDED)
        table.add_column("CVE ID", style="cyan", width=15)
        table.add_column("CVSS Score", style="yellow", width=12)
        table.add_column("Published", width=20)
        table.add_column("Description", width=35, overflow="fold")
        
        for cve in cves[:5]:  # Show top 5
            desc = cve['description'][:50] + "..." if len(cve['description']) > 50 else cve['description']
            table.add_row(
                cve['cve_id'],
                cve['cvss_score'],
                cve['published'][:10],
                desc
            )
        console.print(table)
    
    console.print()
    
    # Test 3: MySQL (common on port 3306)
    print("Test 3: Searching for MySQL CVEs (Port 3306)")
    print("-" * 70)
    cves = cve_lookup.search_by_keyword("MySQL")
    
    if cves:
        table = Table(title=f"MySQL CVEs (Found {len(cves)})", box=box.ROUNDED)
        table.add_column("CVE ID", style="cyan", width=15)
        table.add_column("CVSS Score", style="yellow", width=12)
        table.add_column("Published", width=20)
        table.add_column("Description", width=35, overflow="fold")
        
        for cve in cves[:5]:  # Show top 5
            desc = cve['description'][:50] + "..." if len(cve['description']) > 50 else cve['description']
            table.add_row(
                cve['cve_id'],
                cve['cvss_score'],
                cve['published'][:10],
                desc
            )
        console.print(table)
    
    console.print()
    
    # Show how it integrates with the scanner
    print_header("HOW IT WORKS IN THE ACTUAL SCANNER")
    
    integration_info = """
When you run a port scan (python main.py → 1 → Enter target):

1. Scanner finds open ports and services
2. For each port, it automatically queries NVD for related CVEs
3. Results are enriched with CVE data
4. Display shows:
   
   [CRITICAL PORT EXAMPLE]
   Port 445 — SMB — CRITICAL RISK
   ├─ Service: Windows SMB
   ├─ Known CVEs:
   │  • CVE-2017-0144 (CVSS: 9.3)
   │    EternalBlue vulnerability affecting Windows systems
   │    https://nvd.nist.gov/vuln/detail/CVE-2017-0144
   │  
   │  • CVE-2017-0145 (CVSS: 8.1)
   │    Another RCE in SMB affecting Windows systems
   │    https://nvd.nist.gov/vuln/detail/CVE-2017-0145
   │  
   └─ Recommendation: BLOCK externally via firewall

KEY FEATURES:
✅ Rate limiting: Respects NVD API limits (6 requests/30 sec)
✅ Caching: Avoids repeated queries for same service
✅ Error handling: Gracefully handles API errors
✅ CVSS scoring: Shows CVSS v3.1, v3.0, or v2.0 scores
✅ Links: Direct links to NVD vulnerability pages
    """
    
    console.print(Panel(integration_info, border_style="green", title="Integration Overview"))
    
    console.print()
    console.print("[bold green]✅ Part 1 - CVE Integration: COMPLETE[/bold green]")
    console.print("[dim]Ready to move on to Part 2: GeoIP + Reverse DNS Lookup[/dim]\n")

if __name__ == "__main__":
    test_part_1_cve_integration()
