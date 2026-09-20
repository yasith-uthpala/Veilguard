"""
Unit tests for Veilguard Web Server & REST API
"""

import urllib.request
import json
import pytest
from src.web.server import start_web_server


class TestWebServer:
    """Test web server endpoints and static file delivery."""

    @pytest.fixture(scope="class")
    def running_server(self):
        # Start server on ephemeral port
        server = start_web_server(host="127.0.0.1", port=8123, open_browser=False, in_background=True)
        yield "http://127.0.0.1:8123"
        if server:
            server.shutdown()

    def test_serve_index_html(self, running_server):
        req = urllib.request.Request(f"{running_server}/")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            content = resp.read().decode("utf-8")
            assert "VEILGUARD" in content
            assert "Operations Center" in content

    def test_api_stats(self, running_server):
        req = urllib.request.Request(f"{running_server}/api/stats")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "online"
            assert "system_verdict" in data
            assert "active_sockets" in data
            assert "threat_indicators" in data

    def test_api_network(self, running_server):
        req = urllib.request.Request(f"{running_server}/api/network")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert "bytes_sent" in data
            assert "bytes_recv" in data
            assert "total_packets" in data

    def test_api_blocked(self, running_server):
        req = urllib.request.Request(f"{running_server}/api/blocked")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert "active_hosts_blocks" in data
            assert isinstance(data["active_hosts_blocks"], list)

    def test_api_inspect_validation(self, running_server):
        req = urllib.request.Request(
            f"{running_server}/api/inspect",
            data=b"{}",
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req) as resp:
                pass
        except urllib.error.HTTPError as e:
            assert e.code == 400
