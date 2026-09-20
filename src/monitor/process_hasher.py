"""
Veilguard — Process Forensics & Binary Hashing Module

Capabilities:
  1. Fast chunked SHA-256 hashing of executables.
  2. Deep process forensics: PID, command-line, parent process hierarchy.
  3. Untrusted execution path detection (%TEMP%, AppData, Downloads).
  4. Parent-child Living-off-the-Land (LOLBAS) anomaly detection.
  5. Safe process termination with protected system whitelist.
"""

import os
import sys
import hashlib
import psutil
import datetime
from typing import Dict, Optional, Tuple, List
from rich.console import Console

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console()

# Critical Windows binaries that must NEVER be terminated
PROTECTED_SYSTEM_PROCESSES = {
    "system", "system idle process", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe", "dwm.exe",
    "explorer.exe", "spoolsv.exe", "fontdrvhost.exe", "sihost.exe",
    "taskhostw.exe", "registry", "memory compression"
}

# Suspicious directories where malware frequently drops executables
SUSPICIOUS_PATH_KEYWORDS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
    "\\users\\public\\", "\\downloads\\", "\\perflogs\\",
    "\\var\\tmp\\", "\\dev\\shm\\"
]

# Living-off-the-Land (LOLBAS) binaries frequently abused by droppers
LOLBAS_CHILDREN = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "cscript.exe", "wscript.exe",
    "mshta.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe",
    "vssadmin.exe", "wmic.exe", "schtasks.exe"
}

# Office, PDF, and browser applications that should rarely spawn command shells
OFFICE_AND_BROWSERS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "acrobat.exe", "chrome.exe", "msedge.exe",
    "brave.exe", "firefox.exe", "opera.exe"
}


class ProcessHasher:
    """Provides file hashing and forensic analysis for running processes."""

    @staticmethod
    def compute_sha256(filepath: str) -> Optional[str]:
        """
        Compute SHA-256 hash of a file on disk using 64KB stream chunks.
        Returns hex string or None if unreadable.
        """
        if not filepath or not os.path.isfile(filepath):
            return None

        sha256_func = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256_func.update(chunk)
            return sha256_func.hexdigest().lower()
        except (PermissionError, OSError):
            return None

    @classmethod
    def is_suspicious_path(cls, exe_path: Optional[str]) -> bool:
        """Check if an executable runs from an untrusted temporary or user-writable directory."""
        if not exe_path or exe_path == "—":
            return False
        normalized = "\\" + exe_path.lower().replace("/", "\\").lstrip("\\")
        return any(keyword in normalized for keyword in SUSPICIOUS_PATH_KEYWORDS)

    @classmethod
    def is_parent_anomaly(cls, proc_name: str, parent_name: Optional[str]) -> bool:
        """Detect suspicious parent-child execution (e.g. Word/Browser launching PowerShell/cmd)."""
        if not parent_name:
            return False
        p_child = proc_name.lower()
        p_parent = parent_name.lower()
        return (p_child in LOLBAS_CHILDREN) and (p_parent in OFFICE_AND_BROWSERS)

    @classmethod
    def is_protected_system_process(cls, proc_name: str) -> bool:
        """Check if a process is a vital Windows OS component."""
        return proc_name.lower() in PROTECTED_SYSTEM_PROCESSES

    @classmethod
    def get_process_forensics(cls, pid: int) -> Optional[Dict]:
        """
        Extract comprehensive forensic metadata for a given process PID.
        Returns dict with process details and calculated risk indicators.
        """
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            is_system = cls.is_protected_system_process(name)

            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = None

            sha256_hash = cls.compute_sha256(exe) if exe else None

            try:
                cmdline_list = proc.cmdline()
                cmdline = " ".join(cmdline_list) if cmdline_list else ""
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmdline = ""

            try:
                parent = proc.parent()
                ppid = parent.pid if parent else None
                parent_name = parent.name() if parent else None
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                ppid = None
                parent_name = None

            try:
                cwd = proc.cwd()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cwd = None

            try:
                create_time = datetime.datetime.fromtimestamp(proc.create_time()).isoformat()
            except Exception:
                create_time = None

            try:
                mem_mb = round(proc.memory_info().rss / (1024 * 1024), 2)
            except Exception:
                mem_mb = 0.0

            # Evaluate behavioral flags
            suspicious_path = cls.is_suspicious_path(exe)
            parent_anomaly = cls.is_parent_anomaly(name, parent_name)

            return {
                "pid": pid,
                "name": name,
                "exe": exe or "—",
                "sha256": sha256_hash,
                "cmdline": cmdline,
                "ppid": ppid,
                "parent_name": parent_name or "—",
                "cwd": cwd or "—",
                "created_at": create_time,
                "memory_mb": mem_mb,
                "status": proc.status(),
                "is_suspicious_path": suspicious_path,
                "is_parent_anomaly": parent_anomaly,
                "is_system_proc": is_system,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    @classmethod
    def get_network_processes(cls) -> List[Dict]:
        """
        Scan all processes that currently have active TCP or UDP network connections,
        and enrich each with forensic data (SHA-256, path, parent).
        """
        results = []
        seen_pids = set()

        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return results

        # Group connections by PID
        pid_conns = {}
        for conn in connections:
            if not conn.pid:
                continue

            raddr_str = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
            if conn.pid not in pid_conns:
                pid_conns[conn.pid] = []
            if raddr_str and raddr_str not in pid_conns[conn.pid]:
                pid_conns[conn.pid].append(raddr_str)

        for pid, conns in pid_conns.items():
            if pid in seen_pids:
                continue
            seen_pids.add(pid)
            forensics = cls.get_process_forensics(pid)
            if forensics:
                forensics["remote_connections"] = conns
                results.append(forensics)

        return results

    @classmethod
    def terminate_process(cls, pid: int, force: bool = True) -> Tuple[bool, str]:
        """
        Safely terminate a malicious process.
        Will refuse to kill critical Windows OS processes.
        """
        try:
            proc = psutil.Process(pid)
            name = proc.name()

            if cls.is_protected_system_process(name):
                return False, f"Refused: {name} (PID {pid}) is a protected Windows system process."

            if force:
                proc.kill()
            else:
                proc.terminate()

            proc.wait(timeout=3)
            return True, f"Successfully terminated {name} (PID {pid})."
        except psutil.NoSuchProcess:
            return True, f"Process (PID {pid}) is already gone."
        except psutil.AccessDenied:
            return False, f"Access denied terminating PID {pid}. Administrator privileges required."
        except Exception as e:
            return False, f"Failed to terminate PID {pid}: {e}"


# Singleton instance
process_hasher = ProcessHasher()
