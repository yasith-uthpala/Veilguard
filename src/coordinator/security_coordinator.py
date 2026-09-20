"""
Veilguard — Autonomous Multi-Agent Security Coordinator

The central orchestration brain connecting:
  - Network Monitor (packet flow, exfiltration spikes, port alerts)
  - DNS / Website Monitor (domain queries, Abuse.ch feeds, sinkholing)
  - Process Monitor & Hasher (PID forensics, binary SHA-256, parent-child checks)
  - Threat Intelligence (VirusTotal IP/Domain/File APIs, GeoIP)
  - Site Blocker & Remediator (hosts file, firewall, process termination)

Provides cross-agent correlation, composite risk scoring (0-100), automated
incident logging, and defensive remediation.
"""

import sys
import time
import queue
import threading
import datetime
from typing import Dict, List, Optional, Tuple, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console()

SUSPICIOUS_PORTS = {4444, 1337, 31337, 5555, 6666, 7777, 9999, 8888, 11111, 22222}


class SecurityCoordinator:
    """Orchestrates cross-agent threat correlation, risk scoring, and remediation."""

    def __init__(self, db=None):
        if db is None:
            try:
                from src.db.database import Database
            except ImportError:
                from db.database import Database
            self.db = Database()
        else:
            self.db = db

        try:
            from src.monitor.process_hasher import process_hasher
        except ImportError:
            from monitor.process_hasher import process_hasher
        self.hasher = process_hasher

        try:
            from src.scanner.threat_lookup import ThreatLookup
        except ImportError:
            from scanner.threat_lookup import ThreatLookup
        self.threat_lookup = ThreatLookup()

        try:
            from src.monitor.site_blocker import site_blocker
        except ImportError:
            from monitor.site_blocker import site_blocker
        self.site_blocker = site_blocker

        try:
            from src.monitor.notifier import notifier
        except ImportError:
            from monitor.notifier import notifier
        self.notifier = notifier
        self.silent_mode = False

        self.event_queue: queue.Queue = queue.Queue()
        self.is_running: bool = False
        self._worker_thread: Optional[threading.Thread] = None
        self._subscribers: List[Any] = []
        self._lock = threading.Lock()

    # ---------------------------------------------------------------------------
    # Event Bus Architecture
    # ---------------------------------------------------------------------------

    def start(self):
        """Start the background event correlation worker."""
        if self.is_running:
            return
        self.is_running = True
        self._worker_thread = threading.Thread(target=self._process_event_loop, daemon=True)
        self._worker_thread.start()

    def stop(self):
        """Stop the background event correlation worker."""
        self.is_running = False

    def emit_event(self, event_type: str, data: dict):
        """Publish a security event to the coordinator event bus."""
        event = {
            "type": event_type,
            "timestamp": datetime.datetime.now().isoformat(),
            **data
        }
        self.event_queue.put(event)

    def _process_event_loop(self):
        """Background worker consuming security events from agents."""
        while self.is_running:
            try:
                event = self.event_queue.get(timeout=1.0)
                self.correlate_and_investigate(event)
                self.event_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                console.print(f"[dim]Coordinator loop error: {e}[/dim]")

    # ---------------------------------------------------------------------------
    # Cross-Agent Correlation & Risk Scoring Engine
    # ---------------------------------------------------------------------------

    def compute_risk_score(self, forensics: Optional[dict], file_rep: Optional[dict],
                           threat_intel: Optional[dict], remote_port: Optional[int],
                           is_exfiltration: bool = False) -> Tuple[int, str, List[str]]:
        """
        Calculates composite threat score (0 to 100) and severity rating.
        Returns: (score, severity, reasons)
        """
        score = 0
        reasons = []

        # 1. Binary / File Reputation (+50 for malware, +25 for suspicious)
        if file_rep:
            verdict = file_rep.get("verdict")
            if verdict == "malicious":
                score += 50
                reasons.append(f"Antivirus engine flagged executable as MALICIOUS ({file_rep.get('threat_label', 'Malware')})")
            elif verdict == "suspicious":
                score += 25
                reasons.append("Antivirus engine flagged executable as SUSPICIOUS")

        # 2. Remote Destination Threat Intelligence (+40 for Abuse.ch feed match)
        if threat_intel:
            score += 40
            source = threat_intel.get("source", "feed")
            t_type = threat_intel.get("threat_type", "threat")
            reasons.append(f"Remote destination listed in {source.upper()} feed ({t_type.upper()})")

        # 3. Metasploit / Botnet C2 Port (+25)
        if remote_port and remote_port in SUSPICIOUS_PORTS:
            score += 25
            reasons.append(f"Connection targeting known C2/Trojan port {remote_port}")

        # 4. Bandwidth Exfiltration Burst (+25)
        if is_exfiltration:
            score += 25
            reasons.append("High-volume data exfiltration burst detected")

        # 5. Process Forensic Anomalies
        if forensics:
            if forensics.get("is_suspicious_path"):
                score += 20
                reasons.append(f"Process running from untrusted/temporary directory ({forensics.get('exe')})")

            if forensics.get("is_parent_anomaly"):
                score += 25
                reasons.append(f"Living-off-the-Land anomaly: {forensics.get('name')} spawned by {forensics.get('parent_name')}")

        # Cap score at 100
        score = min(100, score)

        if score >= 75:
            severity = "CRITICAL"
        elif score >= 50:
            severity = "HIGH"
        elif score >= 25:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return score, severity, reasons

    def correlate_and_investigate(self, event: dict) -> dict:
        """
        Main multi-agent investigation routine:
          1. Enriches process forensics (PID, EXE path, SHA-256).
          2. Queries VirusTotal file hash reputation.
          3. Checks remote IP / domain against Abuse.ch feeds & VirusTotal.
          4. Computes composite risk score.
          5. Triggers active remediation if critical.
          6. Persists incident to SQLite.
        """
        pid = event.get("pid")
        domain = event.get("domain")
        remote_ip = event.get("remote_ip")
        remote_port = event.get("remote_port")
        event_type = event.get("type", "ANOMALY")
        is_exfil = event.get("is_exfiltration", False)

        # 1. Process Forensics
        forensics = None
        if pid and isinstance(pid, int):
            forensics = self.hasher.get_process_forensics(pid)

        process_name = forensics.get("name") if forensics else event.get("process_name", "Unknown")
        exe_path = forensics.get("exe") if forensics else event.get("exe_path", "")
        sha256 = forensics.get("sha256") if forensics else None

        # 2. File Hash Reputation
        file_rep = None
        if sha256:
            try:
                file_rep = self.threat_lookup.lookup_file_hash(sha256)
            except Exception:
                file_rep = None

        # 3. Remote Destination Threat Intelligence
        threat_intel = None
        if domain:
            threat_intel = self.db.lookup_threat(domain)
        elif remote_ip:
            threat_intel = self.db.lookup_threat(remote_ip)

        # 4. Composite Risk Scoring
        risk_score, severity, reasons = self.compute_risk_score(
            forensics=forensics,
            file_rep=file_rep,
            threat_intel=threat_intel,
            remote_port=remote_port,
            is_exfiltration=is_exfil
        )

        summary = "; ".join(reasons) if reasons else f"Observed {event_type} on {process_name}"
        action_taken = "LOGGED"

        # 5. Automated Defense & Remediation
        if severity == "CRITICAL":
            # Auto-block domain or IP sinkhole
            if domain:
                self.site_blocker.block_domain(domain, reason=f"Risk Score {risk_score}/100: {event_type}")
                action_taken = "BLOCKED_DOMAIN"

            # Urgent desktop notification
            try:
                self.notifier.send(
                    title=f"🚨 Veilguard Critical Incident ({risk_score}/100)",
                    message=f"{process_name} (PID {pid}) — {reasons[0] if reasons else 'High Threat'}",
                    key=f"crit:{pid}:{domain or remote_ip}",
                    urgency="critical"
                )
            except Exception:
                pass

        elif severity == "HIGH":
            try:
                self.notifier.send(
                    title=f"⚠️ Veilguard Security Alert ({risk_score}/100)",
                    message=f"{process_name}: {reasons[0] if reasons else 'Suspicious Activity'}",
                    key=f"high:{pid}:{domain or remote_ip}",
                    urgency="normal"
                )
                action_taken = "ALERTED_USER"
            except Exception:
                pass

        # 6. Save Incident to Database
        incident_record = {
            "timestamp": event.get("timestamp", datetime.datetime.now().isoformat()),
            "severity": severity,
            "risk_score": risk_score,
            "event_type": event_type,
            "process_name": process_name,
            "pid": pid,
            "exe_path": exe_path,
            "sha256": sha256 or "",
            "remote_ip": remote_ip or "",
            "remote_port": remote_port,
            "domain": domain or "",
            "summary": summary,
            "action_taken": action_taken,
            "details": {
                "reasons": reasons,
                "forensics": forensics,
                "file_reputation": file_rep,
                "threat_intel": threat_intel,
                "raw_event": event
            }
        }

        try:
            inc_id = self.db.save_incident(incident_record)
            incident_record["id"] = inc_id
        except Exception:
            pass

        return incident_record

    # ---------------------------------------------------------------------------
    # Interactive CLI Sweeps & Inspection Routines
    # ---------------------------------------------------------------------------

    def audit_network_processes(self, max_processes: int = 50) -> List[Dict]:
        """
        Scan all active network-connected processes, compute SHA-256 hashes,
        cross-check reputations, and rank by threat risk.
        """
        console.print("\n[bold cyan]🔍 Performing Cross-Agent Network Process Audit...[/bold cyan]")
        console.print("[dim]Extracting PIDs, executable paths, SHA-256 binary hashes, and threat reputations...[/dim]\n")

        raw_procs = self.hasher.get_network_processes()
        if not raw_procs:
            console.print("[yellow]No active network-connected user processes detected.[/yellow]")
            return []

        audited = []
        with console.status("[cyan]Hashing binaries and querying threat intelligence...[/cyan]"):
            for proc in raw_procs[:max_processes]:
                pid = proc["pid"]
                sha256 = proc.get("sha256")
                name = proc.get("name")
                conns = proc.get("remote_connections", [])

                # Check file reputation (fast cached evaluation, reserving API quota for threats)
                file_rep = None
                if sha256:
                    cached_rep = self.threat_lookup._file_cache.get(sha256) or self.db.get_file_hash_cache(sha256)
                    if cached_rep:
                        file_rep = cached_rep
                    elif proc.get("is_system_proc") or (proc.get("exe", "").lower().startswith("c:\\windows\\") and not proc.get("is_suspicious_path")):
                        file_rep = {"verdict": "clean", "verdict_label": "System Binary", "cached": True}
                    elif proc.get("is_suspicious_path") or proc.get("is_parent_anomaly"):
                        file_rep = self.threat_lookup.lookup_file_hash(sha256)
                    else:
                        file_rep = {"verdict": "clean", "verdict_label": "Trusted / Known", "cached": False}

                # Check if any remote connection hits Abuse.ch or suspicious port
                hit_c2 = None
                remote_port = None
                for conn_str in conns:
                    try:
                        ip_part, port_part = conn_str.split(":")
                        p_int = int(port_part)
                        if p_int in SUSPICIOUS_PORTS:
                            remote_port = p_int
                        intel = self.db.lookup_threat(ip_part)
                        if intel:
                            hit_c2 = intel
                            break
                    except Exception:
                        pass

                score, severity, reasons = self.compute_risk_score(
                    forensics=proc,
                    file_rep=file_rep,
                    threat_intel=hit_c2,
                    remote_port=remote_port,
                    is_exfiltration=False
                )

                proc["risk_score"] = score
                proc["severity"] = severity
                proc["reasons"] = reasons
                proc["file_reputation"] = file_rep
                audited.append(proc)

        # Sort descending by risk score
        audited.sort(key=lambda x: x["risk_score"], reverse=True)

        # Build table
        table = Table(
            title=f"Network Process Audit [{len(audited)} Processes Monitored]",
            box=box.SIMPLE_HEAD,
            border_style="purple"
        )
        table.add_column("PID", width=7, style="dim")
        table.add_column("Process Name", width=18, style="cyan")
        table.add_column("Risk", width=10)
        table.add_column("SHA-256 Hash", width=20, style="dim")
        table.add_column("Reputation", width=16)
        table.add_column("Parent", width=16, style="dim")
        table.add_column("Active Remote Sockets", style="white")

        for p in audited:
            score = p["risk_score"]
            color = "red" if score >= 75 else "yellow" if score >= 40 else "green"
            risk_label = f"[{color}]{score}/100[/{color}]"

            rep = p.get("file_reputation", {})
            rep_label = rep.get("verdict_label", "Clean") if rep else "Clean"
            if rep and rep.get("verdict") == "malicious":
                rep_label = f"[bold red]{rep_label}[/bold red]"
            elif rep and rep.get("verdict") == "suspicious":
                rep_label = f"[yellow]{rep_label}[/yellow]"
            else:
                rep_label = f"[green]{rep_label}[/green]"

            hash_disp = (p.get("sha256")[:16] + "...") if p.get("sha256") else "N/A (Access Denied)"
            conn_disp = ", ".join(p.get("remote_connections", [])[:3]) or "Listening / Idle"

            table.add_row(
                str(p["pid"]),
                p["name"],
                risk_label,
                hash_disp,
                rep_label,
                p.get("parent_name", "—"),
                conn_disp
            )

        console.print(table)
        return audited

    def inspect_process(self, pid_or_name: str):
        """Deep forensic inspection for a single process."""
        target_pid = None
        if pid_or_name.isdigit():
            target_pid = int(pid_or_name)
        else:
            # Search by name
            import psutil
            for proc in psutil.process_iter(attrs=["pid", "name"]):
                if proc.info["name"].lower() == pid_or_name.lower():
                    target_pid = proc.info["pid"]
                    break

        if not target_pid:
            console.print(f"[red]❌ Process '{pid_or_name}' not found.[/red]")
            return

        forensics = self.hasher.get_process_forensics(target_pid)
        if not forensics:
            console.print(f"[red]❌ Could not inspect PID {target_pid} (Process terminated or Access Denied).[/red]")
            return

        sha256 = forensics.get("sha256")
        file_rep = None
        if sha256:
            with console.status("[dim]Querying VirusTotal reputation...[/dim]"):
                file_rep = self.threat_lookup.lookup_file_hash(sha256)

        score, severity, reasons = self.compute_risk_score(
            forensics=forensics,
            file_rep=file_rep,
            threat_intel=None,
            remote_port=None,
            is_exfiltration=False
        )

        sev_color = "red" if severity in ("CRITICAL", "HIGH") else "green"
        console.print(Panel.fit(
            f"[bold cyan]{forensics['name']}[/bold cyan] (PID: {forensics['pid']})\n"
            f"Risk Score: [{sev_color}]{score}/100 ({severity})[/{sev_color}]\n"
            f"Executable: [dim]{forensics['exe']}[/dim]\n"
            f"SHA-256:    [bold yellow]{sha256 or 'N/A'}[/bold yellow]\n"
            f"Parent:     {forensics['parent_name']} (PID: {forensics['ppid']})\n"
            f"Command:    [dim]{forensics['cmdline'][:120] + ('...' if len(forensics['cmdline']) > 120 else '')}[/dim]\n"
            f"Memory:     {forensics['memory_mb']} MB\n"
            f"Suspicious Path: {'[red]YES[/red]' if forensics['is_suspicious_path'] else '[green]No[/green]'}\n"
            f"Parent Anomaly:  {'[red]YES[/red]' if forensics['is_parent_anomaly'] else '[green]No[/green]'}\n"
            f"Reputation: {file_rep.get('verdict_label', 'Clean') if file_rep else 'Clean'}",
            title="🛡️ Process Forensic Card",
            border_style="cyan"
        ))

        if reasons:
            console.print("[bold red]Threat Indicators Detected:[/bold red]")
            for r in reasons:
                console.print(f"  • [red]{r}[/red]")

    def enable_game_boost(self) -> Dict[str, Any]:
        """Activates Ultra Game Boost and silent gaming mode."""
        try:
            from src.optimizer.game_optimizer import game_optimizer
        except ImportError:
            from optimizer.game_optimizer import game_optimizer
        res = game_optimizer.enable_boost()
        self.silent_mode = True
        return res

    def disable_game_boost(self) -> Dict[str, Any]:
        """Restores normal performance scheme and desktop notifications."""
        try:
            from src.optimizer.game_optimizer import game_optimizer
        except ImportError:
            from optimizer.game_optimizer import game_optimizer
        res = game_optimizer.disable_boost()
        self.silent_mode = False
        return res

    def is_gaming_mode_active(self) -> bool:
        """Checks whether silent gaming mode is engaged."""
        try:
            from src.optimizer.game_optimizer import game_optimizer
        except ImportError:
            from optimizer.game_optimizer import game_optimizer
        return game_optimizer.silent_mode

    def get_optimizer_status(self) -> Dict[str, Any]:
        """Returns hardware telemetry and boost state."""
        try:
            from src.optimizer.game_optimizer import game_optimizer
        except ImportError:
            from optimizer.game_optimizer import game_optimizer
        return game_optimizer.get_status()


# Singleton instance
security_coordinator = SecurityCoordinator()
