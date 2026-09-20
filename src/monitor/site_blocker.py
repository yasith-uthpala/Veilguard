"""
Veilguard — Active Website Blocker & Unblocker Module

Enforces real system-level domain blocking on Windows using:
  1. Windows hosts file null-routing (0.0.0.0 <domain>)
  2. Windows Defender Firewall outbound block rules (netsh)
  3. Windows DNS cache flusher (ipconfig /flushdns)

Provides safe, isolated tagging so user-defined hosts entries are never touched,
along with full unblocking and emergency reset capabilities.
"""

import os
import sys
import socket
import subprocess
import re
from typing import List, Optional, Set
from rich.console import Console

console = Console()

# Platform-specific hosts file path
DEFAULT_HOSTS_PATH = (
    r"C:\Windows\System32\drivers\etc\hosts"
    if sys.platform == "win32"
    else "/etc/hosts"
)

BLOCK_TAG = "# [Veilguard Block]"


class SiteBlocker:
    """Manages active blocking and unblocking of malicious domains."""

    def __init__(self, hosts_path: Optional[str] = None):
        self.hosts_path = hosts_path or DEFAULT_HOSTS_PATH

    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Strip protocols, paths, ports, and trailing slashes from domain string."""
        s = domain.strip().lower()
        for prefix in ("https://", "http://", "ftp://"):
            if s.startswith(prefix):
                s = s[len(prefix):]
        s = s.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
        return s.rstrip(".")

    def _flush_dns(self):
        """Flush OS DNS resolver cache."""
        if sys.platform == "win32":
            try:
                subprocess.run(
                    ["ipconfig", "/flushdns"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    check=False
                )
            except Exception as e:
                console.print(f"[dim]DNS flush notice: {e}[/dim]")

    def _add_firewall_rule(self, domain: str, ip: str) -> bool:
        """Add Windows Defender Firewall outbound block rule for an IP."""
        if sys.platform != "win32" or not ip or ip.startswith("127."):
            return False
        try:
            rule_name = f"Veilguard_Block_{domain}"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"remoteip={ip}",
                f"description=Veilguard Active Protection: Blocked {domain}"
            ]
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                check=False
            )
            return res.returncode == 0
        except Exception:
            return False

    def _delete_firewall_rule(self, domain: str) -> bool:
        """Delete Windows Defender Firewall rule for a domain."""
        if sys.platform != "win32":
            return False
        try:
            rule_name = f"Veilguard_Block_{domain}"
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ]
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                check=False
            )
            return res.returncode == 0
        except Exception:
            return False

    def block_domain(self, domain: str, reason: str = "malicious") -> bool:
        """
        Actively block domain by adding 0.0.0.0 sinkhole to hosts file
        and creating a Windows Firewall outbound drop rule.
        """
        clean_domain = self.normalize_domain(domain)
        if not clean_domain or "." not in clean_domain:
            return False

        # Domains to redirect to 0.0.0.0
        domains_to_add = [clean_domain]
        if not clean_domain.startswith("www."):
            domains_to_add.append(f"www.{clean_domain}")

        try:
            # Read existing hosts file
            existing_lines = []
            if os.path.exists(self.hosts_path):
                with open(self.hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                    existing_lines = f.readlines()

            # Check if domain already blocked by Veilguard
            already_blocked = set()
            for line in existing_lines:
                if BLOCK_TAG in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                        already_blocked.add(parts[1].lower())

            new_entries = []
            for d in domains_to_add:
                if d.lower() not in already_blocked:
                    new_entries.append(f"0.0.0.0 {d} {BLOCK_TAG}\n")

            if new_entries:
                with open(self.hosts_path, "a", encoding="utf-8", errors="ignore") as f:
                    # Add newline before appending if needed
                    if existing_lines and not existing_lines[-1].endswith("\n"):
                        f.write("\n")
                    f.writelines(new_entries)

            # Resolve domain to IP to add firewall block
            try:
                ip = socket.gethostbyname(clean_domain)
                if ip and not ip.startswith("0.0.") and not ip.startswith("127."):
                    self._add_firewall_rule(clean_domain, ip)
            except Exception:
                pass

            # Flush DNS cache immediately
            self._flush_dns()
            return True

        except PermissionError:
            console.print("[bold red]❌ Error: Administrator privileges required to block domains in hosts file.[/bold red]")
            return False
        except Exception as e:
            console.print(f"[red]Error blocking domain {clean_domain}: {e}[/red]")
            return False

    def unblock_domain(self, domain: str) -> bool:
        """
        Safely unblock a domain by removing only Veilguard-tagged lines
        and removing the corresponding firewall rule.
        """
        clean_domain = self.normalize_domain(domain)
        if not clean_domain:
            return False

        target_domains = {clean_domain.lower(), f"www.{clean_domain}".lower()}

        try:
            if not os.path.exists(self.hosts_path):
                return False

            with open(self.hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            retained_lines = []
            removed_count = 0

            for line in lines:
                if BLOCK_TAG in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].lower() in target_domains:
                        removed_count += 1
                        continue
                retained_lines.append(line)

            if removed_count > 0:
                with open(self.hosts_path, "w", encoding="utf-8", errors="ignore") as f:
                    f.writelines(retained_lines)

            # Delete firewall rule
            self._delete_firewall_rule(clean_domain)

            # Flush DNS cache
            self._flush_dns()
            return removed_count > 0

        except PermissionError:
            console.print("[bold red]❌ Error: Administrator privileges required to edit hosts file.[/bold red]")
            return False
        except Exception as e:
            console.print(f"[red]Error unblocking domain {clean_domain}: {e}[/red]")
            return False

    def unblock_all(self) -> int:
        """
        Emergency reset: removes ALL Veilguard-tagged entries from the hosts file
        and cleans up firewall rules. User/system entries are untouched.
        Returns count of unblocked domains.
        """
        try:
            if not os.path.exists(self.hosts_path):
                return 0

            with open(self.hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            retained_lines = []
            unblocked_domains: Set[str] = set()

            for line in lines:
                if BLOCK_TAG in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        d = parts[1].lower()
                        clean_d = d.removeprefix("www.")
                        unblocked_domains.add(clean_d)
                        self._delete_firewall_rule(clean_d)
                    continue
                retained_lines.append(line)

            with open(self.hosts_path, "w", encoding="utf-8", errors="ignore") as f:
                f.writelines(retained_lines)

            # Flush DNS cache
            self._flush_dns()
            return len(unblocked_domains)

        except PermissionError:
            console.print("[bold red]❌ Error: Administrator privileges required to edit hosts file.[/bold red]")
            return 0
        except Exception as e:
            console.print(f"[red]Error performing unblock all: {e}[/red]")
            return 0

    def get_active_blocks(self) -> List[str]:
        """Return list of all unique domains currently blocked by Veilguard."""
        try:
            if not os.path.exists(self.hosts_path):
                return []

            with open(self.hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            blocked: Set[str] = set()
            for line in lines:
                if BLOCK_TAG in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        d = parts[1].lower()
                        # Normalize www. prefix for clean listing
                        if d.startswith("www."):
                            d = d[4:]
                        blocked.add(d)

            return sorted(list(blocked))

        except Exception as e:
            console.print(f"[dim]Error reading blocked domains: {e}[/dim]")
            return []

    def is_domain_blocked(self, domain: str) -> bool:
        """Check if a domain is currently blocked in the hosts file."""
        clean_domain = self.normalize_domain(domain)
        active_blocks = set(self.get_active_blocks())
        return clean_domain in active_blocks or clean_domain.removeprefix("www.") in active_blocks


# Module singleton
site_blocker = SiteBlocker()
