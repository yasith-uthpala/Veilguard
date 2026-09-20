import unittest
import time
from datetime import datetime
import os
import tempfile
import sqlite3

from src.monitor.network_monitor import BandwidthAnalyzer
from src.monitor.website_monitor import MaliciousSiteDetector
from src.db.database import Database


class TestBandwidthAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = BandwidthAnalyzer(history_window=60)

    def test_suspicious_port_alert(self):
        bandwidth_data = {
            1001: {
                "name": "suspicious_agent.exe",
                "executable": "C:\\temp\\agent.exe",
                "bytes_in": 1024,
                "bytes_out": 2048,
                "total_bytes": 3072,
                "ports": [4444, 80],
                "connections": {"1.2.3.4": 3072},
                "is_high_bandwidth": False,
                "is_exfiltration_suspected": False,
            }
        }
        # First call establishes baseline tracking
        self.analyzer.analyze_bandwidth(bandwidth_data)
        # Second call triggers port alert
        time.sleep(0.01)
        alerts = self.analyzer.analyze_bandwidth(bandwidth_data)
        port_alerts = [a for a in alerts if a.alert_type == "suspicious_port"]
        self.assertTrue(len(port_alerts) >= 1)
        self.assertEqual(port_alerts[0].pid, 1001)

    def test_exfiltration_alert(self):
        pid = 2002
        # Initialize
        self.analyzer.analyze_bandwidth({
            pid: {"name": "curl.exe", "total_bytes": 0, "ports": [443]}
        })
        time.sleep(0.05)
        # Transmit 10 MB in 0.05s (~200 MB/s, well above 50 MB/s exfiltration threshold)
        alerts = self.analyzer.analyze_bandwidth({
            pid: {"name": "curl.exe", "total_bytes": 10 * 1024 * 1024, "ports": [443]}
        })
        exfil_alerts = [a for a in alerts if a.alert_type == "exfiltration"]
        self.assertTrue(len(exfil_alerts) >= 1)
        self.assertEqual(exfil_alerts[0].severity, "critical")


class TestMaliciousSiteDetector(unittest.TestCase):
    def setUp(self):
        self.detector = MaliciousSiteDetector()

    def test_trusted_domains(self):
        is_safe, threat, level = self.detector.is_safe("google.com")
        self.assertTrue(is_safe)
        self.assertEqual(level, "safe")

        # Subdomain of trusted domain
        is_safe, threat, level = self.detector.is_safe("accounts.google.com")
        self.assertTrue(is_safe)

    def test_blacklist_domains(self):
        is_safe, threat, level = self.detector.is_safe("malware-test.com")
        self.assertFalse(is_safe)
        self.assertEqual(threat, "blacklisted")
        self.assertEqual(level, "critical")

    def test_threat_patterns(self):
        is_safe, threat, level = self.detector.is_safe("paypa1.com")
        self.assertFalse(is_safe)
        self.assertEqual(threat, "phishing")

        is_safe, threat, level = self.detector.is_safe("botnet-master.com")
        self.assertFalse(is_safe)
        self.assertEqual(threat, "c2")


class TestDatabaseCore(unittest.TestCase):
    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)
        self.db = Database()
        self.db.path = self.temp_db_path
        self.db.init()

    def tearDown(self):
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except Exception:
                pass

    def test_table_creation(self):
        with self.db.connect() as conn:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            self.assertIn("scans", tables)
            self.assertIn("website_visits", tables)
            self.assertIn("blocked_sites", tables)
            self.assertIn("website_alerts", tables)

    def test_save_and_retrieve_scan(self):
        sample_results = [{
            "target": "127.0.0.1",
            "ip": "127.0.0.1",
            "hostname": "localhost",
            "port": 80,
            "proto": "tcp",
            "state": "open",
            "service": "http",
            "product": "Apache",
            "is_vulnerable": False,
            "vuln_reason": None,
            "country": "Private Network",
            "city": "N/A",
            "isp": "N/A",
            "is_high_risk": 0,
            "scanned_at": datetime.now().isoformat(),
        }]
        self.db.save_scan(sample_results)
        with self.db.connect() as conn:
            row = conn.execute("SELECT port, service, is_vulnerable FROM scans WHERE target='127.0.0.1'").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], 80)
            self.assertEqual(row[1], "http")
            self.assertEqual(row[2], 0)


if __name__ == "__main__":
    unittest.main()
