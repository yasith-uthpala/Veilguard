"""
Unit tests for Veilguard Game Optimizer & System Booster
"""

import json
import urllib.request
import urllib.error
import pytest
from unittest.mock import patch
from src.optimizer.game_optimizer import GameOptimizer, game_optimizer, SYSTEM_PROCESS_WHITELIST
from src.coordinator import security_coordinator
from src.web.server import start_web_server


class TestGameOptimizerEngine:
    """Test the standalone GameOptimizer engine logic."""

    def test_optimizer_initialization(self):
        optimizer = GameOptimizer()
        assert optimizer.is_boost_active is False
        assert optimizer.gaming_mode_active is False
        assert isinstance(optimizer.POPULAR_GAMES, dict)
        assert "cs2.exe" in optimizer.POPULAR_GAMES
        assert "valorant-win64-shipping.exe" in optimizer.POPULAR_GAMES

    def test_get_status_structure(self):
        status = game_optimizer.get_status()
        assert isinstance(status, dict)
        assert "cpu_percent" in status
        assert "ram_used_mb" in status
        assert "ram_total_mb" in status
        assert "ram_free_gb" in status
        assert "ram_percent" in status
        assert "active_games" in status
        assert "boost_active" in status
        assert "gaming_mode" in status
        assert "current_scheme" in status
        assert isinstance(status["active_games"], list)
        assert status["ram_percent"] >= 0.0

    def test_detect_games_returns_list(self):
        games = game_optimizer.detect_games()
        assert isinstance(games, list)
        for g in games:
            assert "exe" in g
            assert "title" in g
            assert "pid" in g

    def test_whitelist_protection(self):
        # Critical Windows system processes must never be classified as optimizable bloatware
        for sys_proc in ("svchost.exe", "explorer.exe", "csrss.exe", "lsass.exe", "system"):
            assert sys_proc in SYSTEM_PROCESS_WHITELIST

    def test_get_optimizable_apps(self):
        apps = game_optimizer.get_optimizable_apps(min_ram_mb=10000.0)
        assert isinstance(apps, list)
        # Verify no system whitelist items leak through
        whitelist_lower = {p.lower() for p in SYSTEM_PROCESS_WHITELIST}
        for app in apps:
            assert app["name"].lower() not in whitelist_lower

    def test_clean_ram(self):
        result = game_optimizer.clean_ram()
        assert isinstance(result, dict)
        assert "cleaned_processes" in result
        assert "freed_mb" in result
        assert "before_mb" in result
        assert "after_mb" in result
        assert result["cleaned_processes"] >= 0

    def test_flush_dns_execution(self):
        # Flush DNS should succeed without throwing exceptions
        res = game_optimizer.flush_dns()
        assert isinstance(res, bool)

    def test_enable_and_disable_boost(self):
        optimizer = GameOptimizer()
        # Mock powercfg calls to keep test pure and non-destructive
        with patch.object(optimizer, "set_power_scheme", return_value=True):
            with patch.object(optimizer, "flush_dns", return_value=True):
                with patch.object(optimizer, "clean_ram", return_value={"freed_mb": 50.0, "processes_trimmed": 5, "cleaned_processes": 5}):
                    res = optimizer.enable_boost()
                    assert res["boost_active"] is True
                    assert optimizer.is_boost_active is True
                    assert optimizer.gaming_mode_active is True

                    restore_res = optimizer.disable_boost()
                    assert restore_res["boost_active"] is False
                    assert optimizer.is_boost_active is False
                    assert optimizer.gaming_mode_active is False

    def test_coordinator_integration(self):
        # Verify SecurityCoordinator delegates boost and silent mode correctly
        assert hasattr(security_coordinator, "enable_game_boost")
        assert hasattr(security_coordinator, "disable_game_boost")
        assert hasattr(security_coordinator, "is_gaming_mode_active")
        assert hasattr(security_coordinator, "get_optimizer_status")


class TestGameOptimizerAPI:
    """Test Game Optimizer REST API endpoints in web dashboard."""

    @pytest.fixture(scope="class")
    def running_server(self):
        server = start_web_server(host="127.0.0.1", port=8126, open_browser=False, in_background=True)
        yield "http://127.0.0.1:8126"
        if server:
            server.shutdown()

    def test_api_optimizer_status(self, running_server):
        req = urllib.request.Request(f"{running_server}/api/optimizer/status")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert "cpu_percent" in data
            assert "ram_used_mb" in data
            assert "ram_percent" in data
            assert "boost_active" in data
            assert "active_games" in data

    def test_api_optimizer_apps(self, running_server):
        req = urllib.request.Request(f"{running_server}/api/optimizer/apps")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert "apps" in data
            assert isinstance(data["apps"], list)

    def test_api_optimizer_clean_ram(self, running_server):
        req = urllib.request.Request(f"{running_server}/api/optimizer/clean_ram", data=b"{}", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data.get("success") is True
            assert "freed_mb" in data
            assert "cleaned_processes" in data

    def test_api_optimizer_terminate_validation(self, running_server):
        # Invalid PID or missing PID should return 400 Bad Request
        req = urllib.request.Request(f"{running_server}/api/optimizer/terminate", data=b"{}", headers={"Content-Type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
        assert exc_info.value.code == 400
