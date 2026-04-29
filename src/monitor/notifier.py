"""
Veilguard — Windows Desktop Notification Module

Sends Windows toast notifications when threats are detected.
Works even when the terminal is minimised or in the background.

Uses: plyer (cross-platform) with win10toast as fallback.
Install: pip install plyer win10toast

Notification types:
  - Malicious IP detected (VirusTotal hit)
  - Suspicious connection (suspicious port)
  - High-risk country connection
  - Bandwidth spike / exfiltration alert
  - New port opened (scheduled scan change detection)
  - File threat detected (future virus guard)
"""

import threading
import time
import os
from datetime import datetime
from typing import Optional
from rich.console import Console

console = Console()

# Veilguard icon path — place veilguard.ico in project root
_ICON_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "veilguard.ico"
)
_ICON_PATH = os.path.abspath(_ICON_PATH) if os.path.exists(
    os.path.abspath(_ICON_PATH)
) else None


class Notifier:
    """
    Send Windows desktop toast notifications.

    Automatically detects the best available notification backend:
      1. plyer   (recommended — works on Windows, Mac, Linux)
      2. win10toast (Windows-only fallback)
      3. Silent  (logs to console only if neither is available)

    Rate-limited: same message won't fire more than once per 60 seconds
    to avoid alert fatigue when the same threat keeps appearing.
    """

    COOLDOWN_SECONDS = 60   # minimum gap between identical notifications

    def __init__(self):
        self._backend     = self._detect_backend()
        self._sent: dict  = {}   # message_key → last_sent timestamp
        self._lock        = threading.Lock()

        if self._backend:
            console.print(f"[dim]Notifications: using {self._backend}[/dim]")
        else:
            console.print(
                "[yellow]Notifications: no backend found — "
                "run 'pip install plyer' to enable toast alerts[/yellow]"
            )

    # ── public API ─────────────────────────────────────────────────────────

    def malicious_ip(self, ip: str, process: str, verdict: str):
        """Alert: VirusTotal flagged a remote IP as malicious."""
        self._send(
            title   = "Veilguard — Malicious IP Detected",
            message = f"{process} connected to {ip}\n{verdict}",
            urgency = "critical",
            key     = f"malicious:{ip}",
        )

    def suspicious_connection(self, process: str, remote: str, reason: str):
        """Alert: process connecting to a suspicious port or address."""
        self._send(
            title   = "Veilguard — Suspicious Connection",
            message = f"{process} → {remote}\n{reason}",
            urgency = "high",
            key     = f"suspicious:{process}:{remote}",
        )

    def high_risk_country(self, ip: str, country: str, process: str):
        """Alert: ESTABLISHED connection to a high-risk country."""
        self._send(
            title   = f"Veilguard — High-Risk Country: {country}",
            message = f"{process} connected to {ip} ({country})",
            urgency = "high",
            key     = f"highrisk:{ip}",
        )

    def bandwidth_spike(self, process: str, mbps: float):
        """Alert: unusual bandwidth spike detected."""
        self._send(
            title   = "Veilguard — Bandwidth Spike",
            message = f"{process} is using {mbps:.1f} MB/s\nPossible data exfiltration",
            urgency = "high",
            key     = f"spike:{process}",
        )

    def exfiltration_suspected(self, process: str, mbps: float):
        """Alert: sustained high bandwidth — possible data exfiltration."""
        self._send(
            title   = "Veilguard — Exfiltration Suspected",
            message = f"{process} sustained {mbps:.1f} MB/s outbound\nReview immediately",
            urgency = "critical",
            key     = f"exfil:{process}",
        )

    def new_port_opened(self, port: int, service: str, risk: str):
        """Alert: a new port has opened since the last scheduled scan."""
        self._send(
            title   = f"Veilguard — New Port Opened: {port}",
            message = f"Service: {service}\nRisk level: {risk}",
            urgency = "high" if risk in ("CRITICAL", "HIGH") else "normal",
            key     = f"newport:{port}",
        )

    def file_threat(self, filepath: str, threat_name: str):
        """Alert: virus guard found a threat in a file (future module)."""
        self._send(
            title   = "Veilguard — Threat Detected",
            message = f"File: {os.path.basename(filepath)}\nThreat: {threat_name}",
            urgency = "critical",
            key     = f"file:{filepath}",
        )

    def custom(self, title: str, message: str, urgency: str = "normal", key: str = ""):
        """Send a custom notification."""
        self._send(title=title, message=message, urgency=urgency,
                   key=key or f"custom:{title}")

    # ── internals ──────────────────────────────────────────────────────────

    def _send(self, title: str, message: str, urgency: str, key: str):
        """Send notification, respecting cooldown and running in a thread."""
        with self._lock:
            now  = time.time()
            last = self._sent.get(key, 0)
            if now - last < self.COOLDOWN_SECONDS:
                return   # still in cooldown for this alert type
            self._sent[key] = now

        # Fire in background thread so it never blocks the UI
        threading.Thread(
            target=self._fire,
            args=(title, message, urgency),
            daemon=True
        ).start()

    def _fire(self, title: str, message: str, urgency: str):
        """Actually send the notification using available backend."""
        # Always log to console regardless of backend
        ts = datetime.now().strftime("%H:%M:%S")
        icon = {"critical": "[bold red]", "high": "[red]", "normal": "[yellow]"}.get(urgency, "[cyan]")
        console.print(f"{icon}[ALERT {ts}][/] {title} — {message}")

        if self._backend == "plyer":
            self._fire_plyer(title, message, urgency)
        elif self._backend == "win10toast":
            self._fire_win10toast(title, message)

    def _fire_plyer(self, title: str, message: str, urgency: str):
        try:
            from plyer import notification
            # plyer timeout: critical=10s, high=7s, normal=5s
            timeout = {"critical": 10, "high": 7}.get(urgency, 5)
            notification.notify(
                title       = title,
                message     = message,
                app_name    = "Veilguard",
                app_icon    = _ICON_PATH or "",
                timeout     = timeout,
            )
        except Exception as e:
            console.print(f"[dim]plyer notification error: {e}[/dim]")

    def _fire_win10toast(self, title: str, message: str):
        try:
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast(
                title,
                message,
                icon_path = _ICON_PATH,
                duration  = 8,
                threaded  = True,
            )
        except Exception as e:
            console.print(f"[dim]win10toast error: {e}[/dim]")

    @staticmethod
    def _detect_backend() -> Optional[str]:
        """Return the best available notification backend, or None."""
        try:
            import plyer  # noqa: F401
            return "plyer"
        except ImportError:
            pass
        try:
            import win10toast  # noqa: F401
            return "win10toast"
        except ImportError:
            pass
        return None


# Module-level singleton — import and use directly:
#   from src.monitor.notifier import notifier
#   notifier.malicious_ip("1.2.3.4", "chrome.exe", "MALICIOUS (3 engines)")
notifier = Notifier()
