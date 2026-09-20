import unittest
from src.scanner.port_scanner import PortScanner, VULNERABLE_PORTS

class TestPortScanner(unittest.TestCase):

    def test_vulnerable_ports_list(self):
        self.assertIn(445, VULNERABLE_PORTS)
        self.assertIn(3389, VULNERABLE_PORTS)
        self.assertIn(21, VULNERABLE_PORTS)

    def test_resolve_localhost(self):
        scanner = PortScanner("localhost")
        ip, hostname, geoip_data = scanner.resolve_host()
        self.assertEqual(ip, "127.0.0.1")
        self.assertIsNotNone(hostname)
        self.assertTrue(geoip_data.get("is_private", False))

    def test_scan_returns_list(self):
        scanner = PortScanner("127.0.0.1")
        results = scanner.scan(port_range="80-81")
        self.assertIsInstance(results, list)

if __name__ == "__main__":
    unittest.main()