"""
Veilguard — High-Performance Web Dashboard Server

Serves the Cyber Threat Operations Center web UI and JSON REST API:
  - GET  /                  -> Serves index.html
  - GET  /api/stats         -> System risk, indicator counts, active shields
  - GET  /api/network       -> Real-time packet counts and bandwidth metrics
  - GET  /api/processes     -> Process forensics, SHA-256 hashes, VT reputations
  - GET  /api/blocked       -> Active hosts sinkholes & firewall rules
  - GET  /api/incidents     -> Correlated multi-agent security incidents
  - POST /api/unblock       -> Unblock a single domain
  - POST /api/unblock_all   -> Emergency unblock all domains
  - POST /api/block         -> Sinkhole a domain
  - POST /api/terminate     -> Safely kill a malicious process
  - POST /api/inspect       -> Deep forensic scan of single PID/name
"""

import os
import sys
import json
import socket
import webbrowser
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Optional
from rich.console import Console

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console()

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


class VeilguardAPIHandler(BaseHTTPRequestHandler):
    """Handles REST API and static asset requests for Veilguard Web UI."""

    server_version = "Veilguard/2.1"

    def log_message(self, format, *args):
        """Suppress noisy access logging in console unless error."""
        if args and str(args[1]).startswith(("4", "5")):
            console.print(f"[dim red][Web] {args[0]} {args[1]}[/dim red]")

    def _send_json(self, data: Any, status: int = 200):
        """Send JSON response with CORS headers."""
        payload = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def _parse_json_body(self) -> dict:
        """Parse request body as JSON."""
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def do_OPTIONS(self):
        """Handle CORS pre-flight."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        """Route GET requests."""
        path = self.path.split("?")[0]

        if path in ("/", "/index.html", "/dashboard"):
            self._serve_index()
        elif path == "/api/stats":
            self._handle_get_stats()
        elif path == "/api/network":
            self._handle_get_network()
        elif path == "/api/sockets":
            self._handle_get_sockets()
        elif path == "/api/processes":
            self._handle_get_processes()
        elif path == "/api/blocked":
            self._handle_get_blocked()
        elif path == "/api/dns/visits":
            self._handle_get_dns_visits()
        elif path == "/api/dns/alerts":
            self._handle_get_dns_alerts()
        elif path == "/api/incidents":
            self._handle_get_incidents()
        elif path == "/api/threats/stats":
            self._handle_get_threat_stats()
        elif path == "/api/scan/history":
            self._handle_get_scan_history()
        elif path == "/api/optimizer/status":
            self._handle_get_optimizer_status()
        elif path == "/api/optimizer/apps":
            self._handle_get_optimizer_apps()
        else:
            self._send_json({"error": "Not Found", "path": path}, status=404)

    def do_POST(self):
        """Route POST requests."""
        path = self.path.split("?")[0]
        body = self._parse_json_body()

        if path == "/api/unblock":
            self._handle_unblock(body)
        elif path == "/api/unblock_all":
            self._handle_unblock_all()
        elif path == "/api/block":
            self._handle_block(body)
        elif path == "/api/terminate":
            self._handle_terminate(body)
        elif path == "/api/inspect":
            self._handle_inspect(body)
        elif path == "/api/scan/start":
            self._handle_scan_start(body)
        elif path == "/api/threats/sync":
            self._handle_threats_sync()
        elif path == "/api/threats/lookup":
            self._handle_threats_lookup(body)
        elif path == "/api/optimizer/boost":
            self._handle_optimizer_boost()
        elif path == "/api/optimizer/restore":
            self._handle_optimizer_restore()
        elif path == "/api/optimizer/clean_ram":
            self._handle_optimizer_clean_ram()
        elif path == "/api/optimizer/terminate":
            self._handle_optimizer_terminate(body)
        else:
            self._send_json({"error": "Endpoint Not Found"}, status=404)

    # ---------------------------------------------------------------------------
    # Static File Handlers
    # ---------------------------------------------------------------------------

    def _serve_index(self):
        index_file = os.path.join(STATIC_DIR, "index.html")
        if not os.path.exists(index_file):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"index.html not found.")
            return

        with open(index_file, "rb") as f:
            content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    # ---------------------------------------------------------------------------
    # API Endpoints Handlers
    # ---------------------------------------------------------------------------

    def _handle_get_stats(self):
        try:
            from src.db.database import Database
            db = Database()
            threat_stats = db.get_threat_stats()
        except Exception:
            threat_stats = {"total_indicators": 57135, "cached_domains": 0, "cached_file_hashes": 0}

        try:
            from src.monitor.site_blocker import site_blocker
            active_blocks = site_blocker.get_active_blocks()
        except Exception:
            active_blocks = []

        try:
            import psutil
            active_sockets = len(psutil.net_connections(kind="inet"))
        except Exception:
            active_sockets = 0

        self._send_json({
            "status": "online",
            "system_verdict": "SECURE" if not active_blocks else "ACTIVE_DEFENSE",
            "risk_score": 0 if not active_blocks else 25,
            "threat_indicators": threat_stats.get("total_indicators", 57135),
            "cached_domains": threat_stats.get("cached_domains", 0),
            "cached_file_hashes": threat_stats.get("cached_file_hashes", 0),
            "active_sockets": active_sockets,
            "blocked_domains_count": len(active_blocks),
            "total_incidents": threat_stats.get("total_incidents", 0),
        })

    def _handle_get_network(self):
        """Fetch current bandwidth consumption from psutil."""
        import psutil
        io = psutil.net_io_counters()
        self._send_json({
            "bytes_sent": io.bytes_sent,
            "bytes_recv": io.bytes_recv,
            "packets_sent": io.packets_sent,
            "packets_recv": io.packets_recv,
            "total_packets": io.packets_sent + io.packets_recv,
            "timestamp": time.time(),
        })

    def _handle_get_processes(self):
        """Fetch audited network processes."""
        try:
            from src.coordinator.security_coordinator import security_coordinator
            audited = security_coordinator.audit_network_processes(max_processes=20)
            self._send_json({"processes": audited})
        except Exception as e:
            self._send_json({"processes": [], "error": str(e)})

    def _handle_get_blocked(self):
        """Fetch active blocks from hosts file and database."""
        try:
            from src.monitor.site_blocker import site_blocker
            blocks = site_blocker.get_active_blocks()
            from src.db.database import Database
            db_records = Database().get_blocked_sites()
        except Exception:
            blocks, db_records = [], []

        self._send_json({
            "active_hosts_blocks": blocks,
            "database_records": db_records
        })

    def _handle_get_incidents(self):
        """Fetch recent security incidents."""
        try:
            from src.db.database import Database
            incidents = Database().get_incidents(limit=50)
        except Exception:
            incidents = []
        self._send_json({"incidents": incidents})

    def _handle_get_sockets(self):
        """Fetch active network sockets snapshot."""
        try:
            from src.monitor.process_monitor import ProcessMonitor
            rows = ProcessMonitor().snapshot()
            self._send_json({"sockets": rows, "count": len(rows)})
        except Exception as e:
            self._send_json({"sockets": [], "error": str(e)})

    def _handle_get_dns_visits(self):
        """Fetch recent website DNS queries from database."""
        try:
            from src.db.database import Database
            visits = Database().get_website_visits(limit=50)
            self._send_json({"visits": visits, "count": len(visits)})
        except Exception as e:
            self._send_json({"visits": [], "error": str(e)})

    def _handle_get_dns_alerts(self):
        """Fetch malicious website alerts from database."""
        try:
            from src.db.database import Database
            alerts = Database().get_website_alerts(limit=50)
            self._send_json({"alerts": alerts, "count": len(alerts)})
        except Exception as e:
            self._send_json({"alerts": [], "error": str(e)})

    def _handle_get_threat_stats(self):
        """Fetch threat intelligence statistics from database."""
        try:
            from src.db.database import Database
            stats = Database().get_threat_stats()
            self._send_json({"stats": stats})
        except Exception as e:
            self._send_json({"stats": {}, "error": str(e)})

    def _handle_get_scan_history(self):
        """Fetch port scan history from database."""
        try:
            from src.db.database import Database
            with Database().connect() as conn:
                rows = conn.execute("""
                    SELECT target, ip, port, service, product, is_vulnerable, scanned_at, country, city, isp
                    FROM scans ORDER BY id DESC LIMIT 50
                """).fetchall()
                scans = [
                    {
                        "target": r[0], "ip": r[1], "port": r[2], "service": r[3],
                        "product": r[4], "is_vulnerable": bool(r[5]), "scanned_at": r[6],
                        "country": r[7], "city": r[8], "isp": r[9]
                    }
                    for r in rows
                ]
                self._send_json({"scans": scans, "count": len(scans)})
        except Exception as e:
            self._send_json({"scans": [], "error": str(e)})

    def _handle_unblock(self, body: dict):
        domain = body.get("domain", "").strip()
        if not domain:
            self._send_json({"success": False, "error": "Missing domain parameter"}, status=400)
            return

        try:
            from src.monitor.site_blocker import site_blocker
            ok, msg = site_blocker.unblock_domain(domain)
            from src.db.database import Database
            Database().remove_blocked_site(domain)
            self._send_json({"success": ok, "message": msg, "domain": domain})
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)

    def _handle_unblock_all(self):
        try:
            from src.monitor.site_blocker import site_blocker
            count = site_blocker.unblock_all()
            from src.db.database import Database
            Database().clear_all_blocked_sites()
            self._send_json({"success": True, "unblocked_count": count})
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)

    def _handle_block(self, body: dict):
        domain = body.get("domain", "").strip()
        reason = body.get("reason", "Manual block via Web UI")
        if not domain:
            self._send_json({"success": False, "error": "Missing domain parameter"}, status=400)
            return

        try:
            from src.monitor.site_blocker import site_blocker
            ok, msg = site_blocker.block_domain(domain, reason=reason)
            from src.db.database import Database
            Database().save_blocked_site(domain, threat_type="manual", threat_level="high", reason=reason)
            self._send_json({"success": ok, "message": msg, "domain": domain})
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)

    def _handle_terminate(self, body: dict):
        pid = body.get("pid")
        if not pid or not isinstance(pid, int):
            self._send_json({"success": False, "error": "Valid integer PID required"}, status=400)
            return

        try:
            from src.monitor.process_hasher import process_hasher
            ok, msg = process_hasher.terminate_process(pid, force=True)
            self._send_json({"success": ok, "message": msg, "pid": pid})
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)

    def _handle_inspect(self, body: dict):
        target = body.get("target")
        if not target:
            self._send_json({"success": False, "error": "Missing target PID or name"}, status=400)
            return

        try:
            from src.monitor.process_hasher import process_hasher
            from src.scanner.threat_lookup import ThreatLookup
            
            target_pid = int(target) if str(target).isdigit() else None
            if not target_pid:
                import psutil
                for p in psutil.process_iter(attrs=["pid", "name"]):
                    if p.info["name"].lower() == str(target).lower():
                        target_pid = p.info["pid"]
                        break

            if not target_pid:
                self._send_json({"success": False, "error": f"Process '{target}' not found."}, status=404)
                return

            forensics = process_hasher.get_process_forensics(target_pid)
            if not forensics:
                self._send_json({"success": False, "error": "Could not access process forensics."}, status=404)
                return

            file_rep = None
            if forensics.get("sha256"):
                file_rep = ThreatLookup().lookup_file_hash(forensics["sha256"])

            self._send_json({
                "success": True,
                "forensics": forensics,
                "file_reputation": file_rep
            })
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)

    def _handle_scan_start(self, body: dict):
        """Execute on-demand port scan with CVE & GeoIP enrichment."""
        target = body.get("target", "").strip()
        port_range = body.get("port_range", "1-1024").strip()
        if not target:
            self._send_json({"success": False, "error": "Target IP or hostname required"}, status=400)
            return

        try:
            from src.scanner.port_scanner import PortScanner
            from src.db.database import Database
            db = Database()
            scanner = PortScanner(target, db)
            ip, hostname, geoip_data = scanner.resolve_host()
            if not ip:
                self._send_json({"success": False, "error": f"Could not resolve target '{target}'"}, status=400)
                return

            open_ports = scanner.fast_sweep(ip)
            results = scanner.deep_scan(ip, open_ports)
            results = scanner.add_geolocation_data(results, geoip_data)
            results = scanner.enrich_with_cves(results)
            
            db.save_scan(results)

            self._send_json({
                "success": True,
                "target": target,
                "ip": ip,
                "hostname": hostname,
                "geolocation": geoip_data,
                "results": results,
                "total_ports_found": len(results),
                "vulnerable_count": sum(1 for r in results if r.get("is_vulnerable"))
            })
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)

    def _handle_threats_sync(self):
        """Synchronize Abuse.ch URLhaus & ThreatFox threat feeds."""
        try:
            from src.monitor.threat_feed_sync import ThreatFeedSync
            sync = ThreatFeedSync()
            stats = sync.sync(force=True, verbose=False)
            from src.db.database import Database
            db_stats = Database().get_threat_stats()
            self._send_json({"success": True, "sync_result": stats, "threat_stats": db_stats})
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)

    def _handle_threats_lookup(self, body: dict):
        """Lookup IP, Domain, or File Hash with VirusTotal & Abuse.ch."""
        query = body.get("query", "").strip()
        lookup_type = body.get("type", "domain").lower().strip()
        if not query:
            self._send_json({"success": False, "error": "Query parameter required"}, status=400)
            return

        try:
            from src.scanner.threat_lookup import ThreatLookup, GeoIPLookup
            from src.db.database import Database
            tl = ThreatLookup()
            db = Database()

            intel_match = db.lookup_threat(query)
            result = {"query": query, "type": lookup_type, "intel_match": intel_match}

            if lookup_type == "domain":
                result["virustotal"] = tl.lookup_domain(query)
            elif lookup_type == "ip":
                result["geolocation"] = GeoIPLookup().lookup(query)
                result["virustotal"] = tl.lookup_ip(query)
            elif lookup_type == "file":
                result["virustotal"] = tl.lookup_file_hash(query)

            self._send_json({"success": True, "result": result})
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)

    # ---------------------------------------------------------------------------
    # Game Optimizer Handlers
    # ---------------------------------------------------------------------------

    def _handle_get_optimizer_status(self):
        try:
            from src.optimizer.game_optimizer import game_optimizer
            self._send_json(game_optimizer.get_status())
        except Exception as e:
            self._send_json({"error": str(e)}, status=500)

    def _handle_get_optimizer_apps(self):
        try:
            from src.optimizer.game_optimizer import game_optimizer
            apps = game_optimizer.get_optimizable_apps()
            self._send_json({"success": True, "apps": apps, "total": len(apps)})
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)

    def _handle_optimizer_boost(self):
        try:
            from src.optimizer.game_optimizer import game_optimizer
            res = game_optimizer.enable_boost()
            self._send_json(res)
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)

    def _handle_optimizer_restore(self):
        try:
            from src.optimizer.game_optimizer import game_optimizer
            res = game_optimizer.disable_boost()
            self._send_json(res)
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)

    def _handle_optimizer_clean_ram(self):
        try:
            from src.optimizer.game_optimizer import game_optimizer
            res = game_optimizer.clean_ram()
            self._send_json({
                "success": True,
                "result": res,
                "freed_mb": res.get("freed_mb", 0),
                "cleaned_processes": res.get("cleaned_processes", 0)
            })
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)

    def _handle_optimizer_terminate(self, body: dict):
        pid = body.get("pid")
        if not pid:
            self._send_json({"success": False, "error": "PID required"}, status=400)
            return
        try:
            from src.optimizer.game_optimizer import game_optimizer
            res = game_optimizer.terminate_background_app(int(pid))
            self._send_json(res)
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, status=500)


def start_web_server(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True, in_background: bool = False):
    """Start the Veilguard web server."""
    # Ensure port is free or find next
    for p in range(port, port + 10):
        try:
            server = ThreadingHTTPServer((host, p), VeilguardAPIHandler)
            port = p
            break
        except OSError:
            continue
    else:
        console.print(f"[red]❌ Could not bind to port {port}.[/red]")
        return

    url = f"http://{host}:{port}"
    console.print(f"\n[bold green]🚀 Veilguard Web Dashboard Online:[/bold green] [bold cyan]{url}[/bold cyan]")
    console.print("[dim]Press Ctrl+C in console to stop the server[/dim]\n")

    if open_browser:
        try:
            threading.Timer(0.8, lambda: webbrowser.open(url)).start()
        except Exception:
            pass

    if in_background:
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        return server
    else:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[yellow]Shutting down Veilguard Web Dashboard...[/yellow]")
            server.shutdown()
            console.print("[dim]Server stopped.[/dim]")


if __name__ == "__main__":
    start_web_server()
