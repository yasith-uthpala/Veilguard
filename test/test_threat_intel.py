import unittest
import os
import tempfile
import sqlite3

from src.scanner.threat_lookup import ThreatLookup
from src.db.database import Database
from src.monitor.threat_feed_sync import ThreatFeedSync


class TestThreatIntelligence(unittest.TestCase):
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

    def test_database_bulk_insert_and_lookup(self):
        sample_threats = [
            {
                "indicator": "malware-sample.xyz",
                "indicator_type": "domain",
                "threat_type": "malware",
                "threat_level": "critical",
                "source": "urlhaus",
                "details": "Active payload host"
            },
            {
                "indicator": "185.120.30.40",
                "indicator_type": "ip",
                "threat_type": "c2",
                "threat_level": "critical",
                "source": "threatfox",
                "details": "Cobalt Strike C2"
            }
        ]

        count = self.db.bulk_insert_threats(sample_threats)
        self.assertEqual(count, 2)

        # Lookup domain
        found = self.db.lookup_threat("malware-sample.xyz")
        self.assertIsNotNone(found)
        self.assertEqual(found["threat_type"], "malware")
        self.assertEqual(found["source"], "urlhaus")

        # Lookup with www. prefix
        found_www = self.db.lookup_threat("www.malware-sample.xyz")
        self.assertIsNotNone(found_www)
        self.assertEqual(found_www["indicator"], "malware-sample.xyz")

        # Lookup IP
        found_ip = self.db.lookup_threat("185.120.30.40")
        self.assertIsNotNone(found_ip)
        self.assertEqual(found_ip["threat_type"], "c2")

        # Lookup unknown returns None
        self.assertIsNone(self.db.lookup_threat("clean-domain-random-987.com"))

    def test_domain_reputation_caching(self):
        sample_vt_data = {
            "verdict": "malicious",
            "verdict_label": "MALICIOUS (12 engines)",
            "malicious": 12,
            "suspicious": 2,
            "harmless": 20,
            "undetected": 40,
            "reputation": -50,
            "total_engines": 74
        }

        self.db.save_domain_cache("phishing-portal.net", sample_vt_data)

        cached = self.db.get_domain_cache("phishing-portal.net")
        self.assertIsNotNone(cached)
        self.assertEqual(cached["verdict"], "malicious")
        self.assertEqual(cached["malicious"], 12)
        self.assertEqual(cached["total_engines"], 74)

    def test_threat_feed_host_extraction(self):
        # Extract from full URLs with paths and ports
        res1 = ThreatFeedSync._extract_host("http://malware-drop.com:8080/payload.exe?v=1")
        self.assertEqual(res1, ("malware-drop.com", "domain"))

        res2 = ThreatFeedSync._extract_host("https://sub.phish.org/login.php")
        self.assertEqual(res2, ("sub.phish.org", "domain"))

        # Extract IPv4 address
        res3 = ThreatFeedSync._extract_host("http://45.198.224.184/ssh")
        self.assertEqual(res3, ("45.198.224.184", "ip"))

        # Filter out comments and loopback
        self.assertIsNone(ThreatFeedSync._extract_host("# Comment line"))
        self.assertIsNone(ThreatFeedSync._extract_host("http://127.0.0.1/test"))
        self.assertIsNone(ThreatFeedSync._extract_host("localhost"))

    def test_threat_lookup_caching(self):
        vt = ThreatLookup()
        # Invalid domain test
        err = vt.lookup_domain("")
        self.assertIn("error", err)

        # Inject cached result to verify caching without burning API quota
        fake_result = {
            "domain": "test-cache.com",
            "verdict": "clean",
            "verdict_label": "Clean",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 70,
            "undetected": 0,
            "reputation": 10,
            "categories": {},
            "total_engines": 70,
            "cached": False
        }
        vt._domain_cache["test-cache.com"] = fake_result

        cached_lookup = vt.lookup_domain("test-cache.com")
        self.assertTrue(cached_lookup["cached"])
        self.assertEqual(cached_lookup["verdict"], "clean")


if __name__ == "__main__":
    unittest.main()
