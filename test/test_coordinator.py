"""
Tests for Multi-Agent Security Coordinator & Process Hashing
"""

import os
import tempfile
import hashlib
import pytest
from src.monitor.process_hasher import ProcessHasher, process_hasher
from src.coordinator.security_coordinator import SecurityCoordinator
from src.db.database import Database


class TestProcessHasher:
    """Test process forensics and binary hashing."""

    def test_compute_sha256(self):
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            content = b"Veilguard multi-agent security test payload"
            f.write(content)
            temp_path = f.name

        try:
            expected_hash = hashlib.sha256(content).hexdigest()
            computed_hash = ProcessHasher.compute_sha256(temp_path)
            assert computed_hash == expected_hash
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_suspicious_path_detection(self):
        assert ProcessHasher.is_suspicious_path("C:\\Users\\John\\AppData\\Local\\Temp\\dropper.exe") is True
        assert ProcessHasher.is_suspicious_path("C:\\Users\\Public\\malware.exe") is True
        assert ProcessHasher.is_suspicious_path("C:\\Users\\John\\Downloads\\payload.exe") is True
        assert ProcessHasher.is_suspicious_path("/tmp/backdoor") is True
        assert ProcessHasher.is_suspicious_path("C:\\Windows\\System32\\svchost.exe") is False
        assert ProcessHasher.is_suspicious_path("C:\\Program Files\\Brave\\brave.exe") is False

    def test_parent_anomaly_detection(self):
        assert ProcessHasher.is_parent_anomaly("powershell.exe", "winword.exe") is True
        assert ProcessHasher.is_parent_anomaly("cmd.exe", "excel.exe") is True
        assert ProcessHasher.is_parent_anomaly("certutil.exe", "chrome.exe") is True
        assert ProcessHasher.is_parent_anomaly("cmd.exe", "explorer.exe") is False
        assert ProcessHasher.is_parent_anomaly("python.exe", "cmd.exe") is False

    def test_protected_system_processes(self):
        assert ProcessHasher.is_protected_system_process("csrss.exe") is True
        assert ProcessHasher.is_protected_system_process("lsass.exe") is True
        assert ProcessHasher.is_protected_system_process("explorer.exe") is True
        assert ProcessHasher.is_protected_system_process("rogue.exe") is False

        # Attempt to kill a system process should be rejected
        ok, msg = ProcessHasher.terminate_process(4)  # PID 4 is 'System' on Windows
        assert ok is False
        assert "Refused" in msg or "protected" in msg


class TestCoordinatorAndRiskScoring:
    """Test cross-agent correlation and risk scoring."""

    @pytest.fixture
    def test_db(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_file = f.name
        db = Database()
        db.path = os.path.abspath(db_file)
        db.init()
        yield db
        if os.path.exists(db_file):
            try:
                os.unlink(db_file)
            except Exception:
                pass

    def test_composite_risk_scoring(self, test_db):
        coord = SecurityCoordinator(db=test_db)

        # 1. Clean process
        score, sev, reasons = coord.compute_risk_score(
            forensics={"name": "python.exe", "is_suspicious_path": False, "is_parent_anomaly": False},
            file_rep={"verdict": "clean"},
            threat_intel=None,
            remote_port=443,
            is_exfiltration=False
        )
        assert score == 0
        assert sev == "LOW"
        assert len(reasons) == 0

        # 2. Critical malware on C2 port + LOLBAS anomaly
        score, sev, reasons = coord.compute_risk_score(
            forensics={
                "name": "powershell.exe",
                "parent_name": "winword.exe",
                "is_suspicious_path": True,
                "is_parent_anomaly": True,
                "exe": "C:\\temp\\evil.exe"
            },
            file_rep={"verdict": "malicious", "threat_label": "Trojan.Dropper"},
            threat_intel={"source": "threatfox", "threat_type": "c2"},
            remote_port=4444,
            is_exfiltration=True
        )
        assert score == 100
        assert sev == "CRITICAL"
        assert len(reasons) >= 5

        # 3. Medium anomaly: Suspicious port and temp path only
        score, sev, reasons = coord.compute_risk_score(
            forensics={"is_suspicious_path": True, "is_parent_anomaly": False, "exe": "C:\\temp\\app.exe"},
            file_rep={"verdict": "clean"},
            threat_intel=None,
            remote_port=4444,
            is_exfiltration=False
        )
        assert score == 45
        assert sev == "MEDIUM"

    def test_database_file_hash_cache(self, test_db):
        sample_hash = "a" * 64
        test_db.save_file_hash_cache(sample_hash, {
            "verdict": "malicious",
            "verdict_label": "MALICIOUS (45/70 engines)",
            "malicious": 45,
            "suspicious": 2,
            "total_engines": 70,
            "threat_label": "Trojan.Win32.Agent",
            "meaningful_name": "malware.exe"
        })

        cached = test_db.get_file_hash_cache(sample_hash)
        assert cached is not None
        assert cached["verdict"] == "malicious"
        assert cached["malicious"] == 45
        assert cached["threat_label"] == "Trojan.Win32.Agent"

    def test_database_incident_persistence(self, test_db):
        inc_id = test_db.save_incident({
            "severity": "CRITICAL",
            "risk_score": 95,
            "event_type": "C2_CONNECTION",
            "process_name": "nc.exe",
            "pid": 9999,
            "exe_path": "C:\\temp\\nc.exe",
            "sha256": "b" * 64,
            "remote_ip": "185.196.8.123",
            "remote_port": 4444,
            "domain": "badc2.org",
            "summary": "Metasploit reverse shell connection",
            "action_taken": "BLOCKED_DOMAIN",
            "details": {"test": "data"}
        })

        assert inc_id > 0
        incidents = test_db.get_incidents(limit=10)
        assert len(incidents) == 1
        assert incidents[0]["process_name"] == "nc.exe"
        assert incidents[0]["risk_score"] == 95
        assert incidents[0]["action_taken"] == "BLOCKED_DOMAIN"
        assert incidents[0]["details"]["test"] == "data"
