"""
Live Network Traffic Monitor - Captures packets and tracks bandwidth per process
Detects unusual spikes and flags potential data exfiltration attempts

FIXES APPLIED:
  Bug 1 - _is_local_address: nested loop variable was shadowing outer variable,
           always returning False so packets never got attributed to processes.
  Bug 2 - _get_pid_from_packet: was calling psutil.net_connections() inside every
           single packet handler — thousands of slow system calls per second on
           Windows meant the process table never populated in time.
  Bug 3 - start_capture: cache was not pre-populated before first packets arrived,
           so the first burst of traffic was always lost.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import psutil
import threading
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
import statistics


@dataclass
class ProcessBandwidth:
    """Tracks bandwidth metrics for a specific process"""
    pid: int
    name: str
    executable: str

    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0

    connections: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    ports: set = field(default_factory=set)

    bandwidth_history: List[Tuple[float, int]] = field(default_factory=list)

    is_high_bandwidth: bool = False
    is_exfiltration_suspected: bool = False
    last_alert_time: float = 0.0
    alert_count: int = 0


@dataclass
class NetworkAlert:
    """Represents a network anomaly alert"""
    timestamp: datetime
    alert_type: str
    pid: int
    process_name: str
    details: str
    severity: str
    bytes_per_second: float


class PacketCapture:
    """Core packet capturing with Scapy and process mapping"""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.process_bandwidth: Dict[int, ProcessBandwidth] = {}
        self.network_interfaces = self._get_network_interfaces()
        self.packet_count = 0
        self.start_time = time.time()
        self.is_capturing = False

        self.ip_to_pid_cache = {}
        self.cache_last_updated = 0
        self.cache_update_interval = 2

        # Cache local IPs so _is_local_address doesn't call psutil every packet
        self._local_ips: set = set()
        self._local_ips_updated = 0

    def _get_network_interfaces(self) -> List[str]:
        try:
            return list(psutil.net_if_addrs().keys())
        except Exception as e:
            print(f"Error getting network interfaces: {e}")
            return []

    def _refresh_local_ips(self):
        """Refresh the set of local IP addresses — called every 10 seconds."""
        now = time.time()
        if now - self._local_ips_updated < 10:
            return
        local = set()
        # FIX Bug 1: net_if_addrs() returns {nic_name: [snicaddr, ...]}
        # The original code had:
        #   for addr in psutil.net_if_addrs().values():   <- addr is a LIST here
        #       for addr in addr:                         <- shadows outer addr!
        # The inner loop never ran because addr (the list) was re-bound.
        for addrs_list in psutil.net_if_addrs().values():  # addrs_list is a list
            for snic in addrs_list:                        # snic is a snicaddr
                local.add(snic.address)
        self._local_ips = local
        self._local_ips_updated = now

    def _is_local_address(self, ip: str) -> bool:
        """Check if IP belongs to this machine."""
        self._refresh_local_ips()
        return ip in self._local_ips

    def _get_local_ip(self) -> str:
        """Get primary outbound IP address."""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _update_ip_to_pid_mapping(self):
        """
        Rebuild the port/IP → PID lookup cache from active connections.
        FIX Bug 2: This is the ONLY place psutil.net_connections() is called.
        It runs on a timer (every 2 s) rather than inside _process_packet,
        so we never do thousands of expensive system calls per second.
        Also maps remote IPs and remote ports, not just local ones.
        """
        if time.time() - self.cache_last_updated < self.cache_update_interval:
            return

        new_cache = {}
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if not conn.pid:
                        continue
                    if conn.laddr:
                        new_cache[str(conn.laddr.port)] = conn.pid
                        new_cache[f"{conn.laddr.ip}:{conn.laddr.port}"] = conn.pid
                        new_cache[conn.laddr.ip] = conn.pid
                    if conn.raddr:
                        new_cache[conn.raddr.ip] = conn.pid
                        new_cache[str(conn.raddr.port)] = conn.pid
                except (psutil.AccessDenied, AttributeError):
                    continue
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        self.ip_to_pid_cache = new_cache
        self.cache_last_updated = time.time()

    def _get_pid_from_packet(self, src_ip: str, dst_ip: str,
                              sport: int, dport: int) -> Optional[int]:
        """
        Look up which PID owns this packet using only the pre-built cache.
        FIX Bug 2: No psutil calls here — cache only.
        """
        try:
            if sport and str(sport) in self.ip_to_pid_cache:
                return self.ip_to_pid_cache[str(sport)]
            if dport and str(dport) in self.ip_to_pid_cache:
                return self.ip_to_pid_cache[str(dport)]
            if src_ip in self.ip_to_pid_cache:
                return self.ip_to_pid_cache[src_ip]
            if dst_ip in self.ip_to_pid_cache:
                return self.ip_to_pid_cache[dst_ip]
            if sport:
                key = f"0.0.0.0:{sport}"
                if key in self.ip_to_pid_cache:
                    return self.ip_to_pid_cache[key]
            if dport:
                key = f"0.0.0.0:{dport}"
                if key in self.ip_to_pid_cache:
                    return self.ip_to_pid_cache[key]
        except Exception:
            pass
        return None

    def _process_packet(self, packet) -> None:
        """
        Handle one captured packet.
        FIX Bug 2: Cache is refreshed here by timer (every 50 packets),
        not by calling net_connections() inline.
        """
        try:
            self.packet_count += 1

            # Refresh cache every 50 packets — fast enough to catch new
            # connections without hammering the OS with system calls
            if self.packet_count % 50 == 0:
                self._update_ip_to_pid_mapping()

            if IP not in packet:
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            sport = dport = protocol = None

            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                protocol = 'TCP'
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                protocol = 'UDP'
            elif ICMP in packet:
                protocol = 'ICMP'
            else:
                protocol = 'OTHER'

            pid = self._get_pid_from_packet(src_ip, dst_ip, sport or 0, dport or 0)

            if pid and pid > 0:
                if pid not in self.process_bandwidth:
                    try:
                        proc = psutil.Process(pid)
                        self.process_bandwidth[pid] = ProcessBandwidth(
                            pid=pid,
                            name=proc.name(),
                            executable=proc.exe() or ""
                        )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        return

                proc_bw = self.process_bandwidth[pid]
                packet_size = len(packet)

                if self._is_local_address(src_ip):
                    proc_bw.bytes_out += packet_size
                    proc_bw.packets_out += 1
                else:
                    proc_bw.bytes_in += packet_size
                    proc_bw.packets_in += 1

                peer_ip = dst_ip if self._is_local_address(src_ip) else src_ip
                proc_bw.connections[peer_ip] += packet_size

                if dport:
                    proc_bw.ports.add(dport)

        except Exception:
            pass

    def start_capture(self, interface: Optional[str] = None) -> None:
        """
        Start packet capture in a background thread.
        FIX Bug 3: Pre-populate the PID cache AND reset the timestamp so
        the very first packets are attributed correctly instead of being lost.
        """
        self.is_capturing = True
        self._refresh_local_ips()

        # Force an immediate cache build before any packets arrive
        self.cache_last_updated = 0
        self._update_ip_to_pid_mapping()

        capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(interface or self.interface,),
            daemon=True
        )
        capture_thread.start()

    def _capture_packets(self, interface: Optional[str]) -> None:
        """Internal scapy sniff loop — runs in its own thread."""
        try:
            sniff(
                prn=self._process_packet,
                iface=interface,
                store=False,
                filter="ip",
                stop_filter=lambda x: not self.is_capturing
            )
        except PermissionError:
            print("ERROR: Packet capture requires Administrator privileges on Windows.")
            print("       Right-click PowerShell → 'Run as Administrator', then retry.")
            self.is_capturing = False
        except Exception as e:
            print(f"Packet capture error: {e}")
            self.is_capturing = False

    def stop_capture(self) -> None:
        self.is_capturing = False

    def get_bandwidth_snapshot(self) -> Dict[int, Dict]:
        """Return a copy of current per-process bandwidth metrics."""
        snapshot = {}
        for pid, proc_bw in self.process_bandwidth.items():
            snapshot[pid] = {
                'name':                    proc_bw.name,
                'executable':              proc_bw.executable,
                'bytes_in':                proc_bw.bytes_in,
                'bytes_out':               proc_bw.bytes_out,
                'packets_in':              proc_bw.packets_in,
                'packets_out':             proc_bw.packets_out,
                'total_bytes':             proc_bw.bytes_in + proc_bw.bytes_out,
                'connections':             dict(proc_bw.connections),
                'ports':                   list(proc_bw.ports),
                'is_high_bandwidth':       proc_bw.is_high_bandwidth,
                'is_exfiltration_suspected': proc_bw.is_exfiltration_suspected,
            }
        return snapshot


class BandwidthAnalyzer:
    """Analyzes bandwidth patterns and detects anomalies"""

    def __init__(self, history_window: int = 60):
        self.history_window = history_window
        self.process_stats: Dict[int, Dict] = {}
        self.alerts: List[NetworkAlert] = []

        self.spike_threshold_multiplier    = 2.5
        self.exfiltration_threshold_mbps   = 50.0
        self.high_bandwidth_threshold_mbps = 100.0
        self.suspicious_ports = {
            4444, 5555, 6666, 7777, 8888, 9999,
            31337, 11111, 22222, 33333,
        }

    def analyze_bandwidth(self, bandwidth_data: Dict[int, Dict]) -> List[NetworkAlert]:
        current_alerts = []
        current_time = datetime.now()

        for pid, data in bandwidth_data.items():
            if pid not in self.process_stats:
                self.process_stats[pid] = {
                    'name':              data['name'],
                    'last_bytes':        data['total_bytes'],
                    'last_check':        current_time,
                    'bandwidth_history': [],
                }

            stats = self.process_stats[pid]
            time_delta = (current_time - stats['last_check']).total_seconds()

            if time_delta > 0:
                bytes_delta  = data['total_bytes'] - stats['last_bytes']
                current_bps  = bytes_delta / time_delta
                current_mbps = current_bps / (1024 * 1024)

                stats['bandwidth_history'].append((current_time, current_bps))

                cutoff_time = current_time - timedelta(seconds=self.history_window)
                stats['bandwidth_history'] = [
                    (t, bps) for t, bps in stats['bandwidth_history']
                    if t > cutoff_time
                ]

                if len(stats['bandwidth_history']) > 3:
                    bps_values = [bps for _, bps in stats['bandwidth_history']]
                    baseline   = statistics.mean(bps_values[:-1]) if len(bps_values) > 1 else 0
                    current    = bps_values[-1]

                    if baseline > 0 and current > baseline * self.spike_threshold_multiplier:
                        current_alerts.append(NetworkAlert(
                            timestamp=current_time,
                            alert_type='spike',
                            pid=pid,
                            process_name=data['name'],
                            details=f"Bandwidth spike: {current_mbps:.2f} MB/s",
                            severity='medium',
                            bytes_per_second=current_bps
                        ))

                if current_mbps > self.high_bandwidth_threshold_mbps:
                    current_alerts.append(NetworkAlert(
                        timestamp=current_time,
                        alert_type='abnormal_volume',
                        pid=pid,
                        process_name=data['name'],
                        details=f"High bandwidth: {current_mbps:.2f} MB/s",
                        severity='medium',
                        bytes_per_second=current_bps
                    ))

                if current_mbps > self.exfiltration_threshold_mbps:
                    current_alerts.append(NetworkAlert(
                        timestamp=current_time,
                        alert_type='exfiltration',
                        pid=pid,
                        process_name=data['name'],
                        details=f"Potential exfiltration: {current_mbps:.2f} MB/s sustained",
                        severity='critical',
                        bytes_per_second=current_bps
                    ))

                suspicious_ports_used = set(data['ports']) & self.suspicious_ports
                if suspicious_ports_used:
                    current_alerts.append(NetworkAlert(
                        timestamp=current_time,
                        alert_type='suspicious_port',
                        pid=pid,
                        process_name=data['name'],
                        details=f"Suspicious ports: {suspicious_ports_used}",
                        severity='high',
                        bytes_per_second=current_bps
                    ))

                stats['last_bytes'] = data['total_bytes']
                stats['last_check'] = current_time

        self.alerts.extend(current_alerts)

        cutoff_time = current_time - timedelta(minutes=10)
        self.alerts = [a for a in self.alerts if a.timestamp > cutoff_time]

        return current_alerts

    def get_bandwidth_per_process(self, bandwidth_data: Dict[int, Dict]) -> List[Tuple[str, int, float]]:
        processes = [
            (data['name'], pid, data['total_bytes'])
            for pid, data in bandwidth_data.items()
        ]
        processes.sort(key=lambda x: x[2], reverse=True)
        return processes

    def get_recent_alerts(self, limit: int = 10) -> List[NetworkAlert]:
        return self.alerts[-limit:]

    def clear_alerts(self) -> None:
        self.alerts.clear()


class NetworkMonitor:
    """Main coordinator — ties PacketCapture and BandwidthAnalyzer together."""

    def __init__(self, interface: Optional[str] = None, update_interval: int = 2):
        self.packet_capture      = PacketCapture(interface)
        self.bandwidth_analyzer  = BandwidthAnalyzer()
        self.update_interval     = update_interval
        self.is_running          = False
        self.snapshots: List[Dict] = []

    def start(self) -> None:
        self.is_running = True
        self.packet_capture.start_capture()

        analysis_thread = threading.Thread(
            target=self._analysis_loop,
            daemon=True
        )
        analysis_thread.start()

    def _analysis_loop(self) -> None:
        while self.is_running:
            try:
                bandwidth_data = self.packet_capture.get_bandwidth_snapshot()
                alerts         = self.bandwidth_analyzer.analyze_bandwidth(bandwidth_data)

                snapshot = {
                    'timestamp':     datetime.now(),
                    'bandwidth_data': bandwidth_data,
                    'alerts':        alerts,
                    'packet_count':  self.packet_capture.packet_count,
                }
                self.snapshots.append(snapshot)

                if len(self.snapshots) > 1000:
                    self.snapshots = self.snapshots[-1000:]

                time.sleep(self.update_interval)
            except Exception as e:
                print(f"Analysis error: {e}")

    def stop(self) -> None:
        self.is_running = False
        self.packet_capture.stop_capture()

    def get_live_stats(self) -> Dict:
        bandwidth_data  = self.packet_capture.get_bandwidth_snapshot()
        top_processes   = self.bandwidth_analyzer.get_bandwidth_per_process(bandwidth_data)
        recent_alerts   = self.bandwidth_analyzer.get_recent_alerts()

        return {
            'bandwidth_data':           bandwidth_data,
            'top_processes':            top_processes,
            'recent_alerts':            recent_alerts,
            'uptime':                   time.time() - self.packet_capture.start_time,
            'packet_count':             self.packet_capture.packet_count,
            'total_processes_monitored': len(self.packet_capture.process_bandwidth),
        }

    def get_process_details(self, pid: int) -> Optional[Dict]:
        bandwidth_data = self.packet_capture.get_bandwidth_snapshot()
        return bandwidth_data.get(pid)

    def export_session_data(self, filepath: str) -> None:
        import json
        export_data = {
            'session_duration':   time.time() - self.packet_capture.start_time,
            'total_packets':      self.packet_capture.packet_count,
            'snapshots_count':    len(self.snapshots),
            'total_alerts':       len(self.bandwidth_analyzer.alerts),
            'processes_monitored': len(self.packet_capture.process_bandwidth),
        }
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
