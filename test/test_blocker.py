import unittest
import os
import tempfile

from src.monitor.site_blocker import SiteBlocker, BLOCK_TAG


class TestSiteBlocker(unittest.TestCase):
    def setUp(self):
        # Create a temporary fake hosts file for safe testing
        self.temp_fd, self.temp_hosts_path = tempfile.mkstemp(suffix=".hosts")
        with os.fdopen(self.temp_fd, "w", encoding="utf-8") as f:
            f.write("# Sample user hosts file\n")
            f.write("127.0.0.1 localhost\n")
            f.write("::1 localhost\n")
            f.write("192.168.1.50 my-dev-server.local\n\n")

        self.blocker = SiteBlocker(hosts_path=self.temp_hosts_path)

    def tearDown(self):
        if os.path.exists(self.temp_hosts_path):
            try:
                os.remove(self.temp_hosts_path)
            except Exception:
                pass

    def test_domain_normalization(self):
        self.assertEqual(SiteBlocker.normalize_domain("https://example.com/path?query=1"), "example.com")
        self.assertEqual(SiteBlocker.normalize_domain("http://sub.domain.org:8080/"), "sub.domain.org")
        self.assertEqual(SiteBlocker.normalize_domain("  MALWARE-SITE.COM.  "), "malware-site.com")

    def test_block_domain(self):
        success = self.blocker.block_domain("malware-test.com")
        self.assertTrue(success)

        with open(self.temp_hosts_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Check entries were appended
        self.assertIn("0.0.0.0 malware-test.com # [Veilguard Block]", content)
        self.assertIn("0.0.0.0 www.malware-test.com # [Veilguard Block]", content)
        # Check original user entries are intact
        self.assertIn("192.168.1.50 my-dev-server.local", content)

        # Check query methods
        self.assertTrue(self.blocker.is_domain_blocked("malware-test.com"))
        self.assertIn("malware-test.com", self.blocker.get_active_blocks())

    def test_unblock_single_domain(self):
        # Block two domains
        self.blocker.block_domain("site-a.com")
        self.blocker.block_domain("site-b.com")
        self.assertEqual(len(self.blocker.get_active_blocks()), 2)

        # Unblock site-a only
        unblocked = self.blocker.unblock_domain("site-a.com")
        self.assertTrue(unblocked)

        blocks = self.blocker.get_active_blocks()
        self.assertNotIn("site-a.com", blocks)
        self.assertIn("site-b.com", blocks)

        # Ensure user entry remains untouched
        with open(self.temp_hosts_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("192.168.1.50 my-dev-server.local", content)

    def test_unblock_all(self):
        self.blocker.block_domain("evil1.com")
        self.blocker.block_domain("evil2.com")
        self.blocker.block_domain("evil3.com")
        self.assertEqual(len(self.blocker.get_active_blocks()), 3)

        count = self.blocker.unblock_all()
        self.assertEqual(count, 3)
        self.assertEqual(len(self.blocker.get_active_blocks()), 0)

        # Original user lines must be completely preserved
        with open(self.temp_hosts_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn(BLOCK_TAG, content)
        self.assertIn("127.0.0.1 localhost", content)
        self.assertIn("192.168.1.50 my-dev-server.local", content)


if __name__ == "__main__":
    unittest.main()
