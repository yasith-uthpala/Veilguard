"""
Veilguard Game Optimizer & High-Performance System Booster.

Features:
- Windows Power Scheme Switching (High/Ultimate Performance vs Balanced)
- Deep Working-Set RAM Purging (ctypes EmptyWorkingSet)
- Background Bloatware & Resource Eater Identification
- Popular Game Auto-Detection
- Low-Latency DNS Cache Flush
- Silent Gaming Mode (Suppresses toast notifications and background overhead)
"""

import os
import sys
import time
import ctypes
import psutil
import subprocess
import re
from datetime import datetime
from typing import Dict, List, Any, Optional

# Popular PC Game Signatures (Executable -> Friendly Title)
KNOWN_GAMES = {
    "cs2.exe": "Counter-Strike 2",
    "csgo.exe": "Counter-Strike: Global Offensive",
    "valorant.exe": "Valorant",
    "valorant-win64-shipping.exe": "Valorant (Riot)",
    "fortniteclient-win64-shipping.exe": "Fortnite",
    "league of legends.exe": "League of Legends",
    "leagueclient.exe": "League of Legends Client",
    "gta5.exe": "Grand Theft Auto V",
    "playgtav.exe": "Grand Theft Auto V",
    "overwatch.exe": "Overwatch 2",
    "minecraft.exe": "Minecraft",
    "javaw.exe": "Minecraft (Java Edition)",
    "cyberpunk2077.exe": "Cyberpunk 2077",
    "dota2.exe": "Dota 2",
    "apexlegends.exe": "Apex Legends",
    "r5apex.exe": "Apex Legends",
    "robloxplayerbeta.exe": "Roblox",
    "genshinimpact.exe": "Genshin Impact",
    "starfield.exe": "Starfield",
    "bg3.exe": "Baldur's Gate 3",
    "bg3_dx11.exe": "Baldur's Gate 3 (DX11)",
    "eldenring.exe": "Elden Ring",
    "destiny2.exe": "Destiny 2",
    "warframe.x64.exe": "Warframe",
    "rocketleague.exe": "Rocket League",
    "rainbowsix.exe": "Tom Clancy's Rainbow Six Siege",
    "r6siege.exe": "Tom Clancy's Rainbow Six Siege",
    "cod.exe": "Call of Duty",
    "steam.exe": "Steam Platform",
    "epicgameslauncher.exe": "Epic Games Launcher"
}

# Critical system processes that should NEVER be terminated or treated as background bloat
SYSTEM_PROCESS_WHITELIST = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "dwm.exe",
    "fontdrvhost.exe", "winlogon.exe", "explorer.exe", "spoolsv.exe",
    "taskhostw.exe", "sihost.exe", "ctfmon.exe", "searchhost.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe", "python.exe",
    "conhost.exe", "runtimebroker.exe", "securityhealthservice.exe",
    "mpcmdrun.exe", "msmpeng.exe"
}

class GameOptimizer:
    """Core engine for game optimization, RAM cleanup, and power plan tuning."""

    POPULAR_GAMES = KNOWN_GAMES

    def __init__(self):
        self.is_boosted = False
        self.boost_timestamp: Optional[str] = None
        self.original_scheme_guid: Optional[str] = None
        self.active_scheme_name: str = "Standard"
        self.silent_mode: bool = False
        self.memory_freed_total_mb: float = 0.0

    @property
    def is_boost_active(self) -> bool:
        return self.is_boosted

    @property
    def gaming_mode_active(self) -> bool:
        return self.silent_mode

    def get_power_schemes(self) -> Dict[str, Any]:
        """Queries Windows power schemes via powercfg."""
        current_guid = None
        current_name = "Unknown"
        schemes = []

        if sys.platform != "win32":
            return {"active_guid": None, "active_name": "Non-Windows", "available": []}

        try:
            out = subprocess.check_output(["powercfg", "/list"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                m = re.search(r"Power Scheme GUID:\s+([a-f0-9\-]+)\s+\(([^)]+)\)(\s+\*)?", line, re.IGNORECASE)
                if m:
                    guid = m.group(1).strip()
                    name = m.group(2).strip()
                    is_active = bool(m.group(3))
                    schemes.append({"guid": guid, "name": name, "is_active": is_active})
                    if is_active:
                        current_guid = guid
                        current_name = name
        except Exception:
            pass

        self.active_scheme_name = current_name
        return {
            "active_guid": current_guid,
            "active_name": current_name,
            "available": schemes
        }

    def set_power_scheme(self, target: str = "high_performance") -> bool:
        """
        Switches Windows power scheme to High Performance or Ultimate Performance.
        target: 'high_performance' or 'restore'
        """
        if sys.platform != "win32":
            return False

        try:
            power_data = self.get_power_schemes()
            current_guid = power_data.get("active_guid")

            if target == "restore":
                if self.original_scheme_guid:
                    subprocess.run(["powercfg", "/setactive", self.original_scheme_guid], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.original_scheme_guid = None
                    return True
                return False

            # We want High or Ultimate performance
            if not self.original_scheme_guid and current_guid:
                self.original_scheme_guid = current_guid

            # Search available schemes for Ultimate or High Performance
            schemes = power_data.get("available", [])
            target_guid = None
            
            # Prefer Ultimate, then High Performance
            for s in schemes:
                if "ultimate" in s["name"].lower():
                    target_guid = s["guid"]
                    break
            if not target_guid:
                for s in schemes:
                    if "high performance" in s["name"].lower():
                        target_guid = s["guid"]
                        break

            # Fallback to standard Windows High Performance GUID if not listed
            if not target_guid:
                target_guid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"

            subprocess.run(["powercfg", "/setactive", target_guid], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    def clean_ram(self) -> Dict[str, Any]:
        """
        Flushes physical RAM working set memory across accessible non-critical processes.
        Returns amount of RAM freed in MB and execution details.
        """
        mem_before = psutil.virtual_memory()
        trimmed_count = 0

        if sys.platform == "win32":
            try:
                psapi = ctypes.windll.psapi
                kernel32 = ctypes.windll.kernel32
                PROCESS_SET_QUOTA = 0x0100
                PROCESS_QUERY_INFORMATION = 0x0400

                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        pname = (proc.info.get('name') or '').lower()
                        if pname in SYSTEM_PROCESS_WHITELIST or proc.pid <= 4:
                            continue

                        h_process = kernel32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION, False, proc.pid)
                        if h_process:
                            res = psapi.EmptyWorkingSet(h_process)
                            kernel32.CloseHandle(h_process)
                            if res:
                                trimmed_count += 1
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception:
                pass

        time.sleep(0.3)
        mem_after = psutil.virtual_memory()
        freed_bytes = max(0, mem_after.available - mem_before.available)
        freed_mb = round(freed_bytes / (1024 * 1024), 1)

        self.memory_freed_total_mb += freed_mb

        return {
            "processes_trimmed": trimmed_count,
            "cleaned_processes": trimmed_count,
            "freed_mb": freed_mb,
            "available_mb": round(mem_after.available / (1024 * 1024), 1),
            "ram_used_percent": mem_after.percent,
            "before_mb": round((mem_before.total - mem_before.available) / (1024 * 1024), 1),
            "after_mb": round((mem_after.total - mem_after.available) / (1024 * 1024), 1)
        }

    def flush_dns_cache(self) -> bool:
        """Flushes DNS cache to clear stale network routing and packet jitter."""
        if sys.platform == "win32":
            try:
                subprocess.run(["ipconfig", "/flushdns"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except Exception:
                return False
        return True

    flush_dns = flush_dns_cache

    def detect_games(self) -> List[Dict[str, Any]]:
        """Scans process list for active running games."""
        running_games = []
        try:
            for p in psutil.process_iter(['pid', 'name', 'create_time']):
                try:
                    name_lower = (p.info.get('name') or '').lower()
                    if name_lower in KNOWN_GAMES:
                        running_games.append({
                            "pid": p.pid,
                            "exe": p.info.get('name'),
                            "title": KNOWN_GAMES[name_lower],
                            "started_at": datetime.fromtimestamp(p.info.get('create_time') or time.time()).strftime("%H:%M:%S")
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        return running_games

    def get_optimizable_apps(self, min_ram_mb: float = 35.0) -> List[Dict[str, Any]]:
        """
        Lists running background processes consuming significant RAM that can be safely closed.
        Excludes games, Windows system binaries, and current IDE/Python tools.
        """
        apps = []
        games_pids = {g["pid"] for g in self.detect_games()}
        current_pid = os.getpid()

        for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent']):
            try:
                if proc.pid in games_pids or proc.pid == current_pid or proc.pid <= 4:
                    continue

                name = proc.info.get('name') or 'unknown'
                name_lower = name.lower()

                if name_lower in SYSTEM_PROCESS_WHITELIST:
                    continue

                mem_mb = round((proc.info.get('memory_info').rss if proc.info.get('memory_info') else 0) / (1024 * 1024), 1)
                if mem_mb >= min_ram_mb:
                    apps.append({
                        "pid": proc.pid,
                        "name": name,
                        "memory_mb": mem_mb,
                        "cpu_percent": proc.info.get('cpu_percent') or 0.0,
                        "is_safe_to_kill": True
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Sort by memory usage descending
        apps.sort(key=lambda x: x["memory_mb"], reverse=True)
        return apps

    def terminate_background_app(self, pid: int) -> Dict[str, Any]:
        """Safely closes an individual background process."""
        try:
            proc = psutil.Process(pid)
            name = proc.name().lower()
            if name in SYSTEM_PROCESS_WHITELIST or pid <= 4:
                return {"success": False, "error": f"Cannot terminate protected system process: {name}"}

            proc.terminate()
            try:
                proc.wait(timeout=2)
            except psutil.TimeoutExpired:
                proc.kill()

            return {"success": True, "message": f"Closed background application PID {pid} ({name})"}
        except psutil.NoSuchProcess:
            return {"success": True, "message": "Process already stopped."}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def enable_boost(self) -> Dict[str, Any]:
        """
        1-Click Ultra Game Boost:
        1. Switches power plan to High/Ultimate Performance
        2. Deep working set RAM cache purge
        3. Flushes DNS cache
        4. Activates silent gaming mode (suppresses toasts)
        """
        # Switch power plan
        power_switched = self.set_power_scheme("high_performance")
        
        # Purge RAM
        ram_result = self.clean_ram()
        
        # Flush DNS
        dns_flushed = self.flush_dns_cache()

        self.is_boosted = True
        self.silent_mode = True
        self.boost_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Notify coordinator if loaded
        try:
            from src.coordinator.security_coordinator import security_coordinator
            security_coordinator.silent_mode = True
        except Exception:
            pass

        return {
            "success": True,
            "is_boosted": True,
            "boost_active": True,
            "power_plan_switched": power_switched,
            "dns_flushed": dns_flushed,
            "ram_freed_mb": ram_result.get("freed_mb", 0),
            "ram_used_percent": ram_result.get("ram_used_percent", 0),
            "boost_timestamp": self.boost_timestamp,
            "active_games": self.detect_games()
        }

    def disable_boost(self) -> Dict[str, Any]:
        """Restores normal system profile and standard notifications."""
        self.set_power_scheme("restore")
        self.is_boosted = False
        self.silent_mode = False
        self.boost_timestamp = None

        try:
            from src.coordinator.security_coordinator import security_coordinator
            security_coordinator.silent_mode = False
        except Exception:
            pass

        return {
            "success": True,
            "is_boosted": False,
            "boost_active": False,
            "message": "Game Boost deactivated. Restored original power plan and normal mode."
        }

    def get_status(self) -> Dict[str, Any]:
        """Returns live hardware telemetry and optimizer states."""
        mem = psutil.virtual_memory()
        cpu_pct = psutil.cpu_percent(interval=None)
        power_info = self.get_power_schemes()
        running_games = self.detect_games()
        ram_used_mb = round((mem.total - mem.available) / (1024 * 1024), 1)
        ram_total_mb = round(mem.total / (1024 * 1024), 1)
        ram_free_gb = round(mem.available / (1024 * 1024 * 1024), 2)

        return {
            "is_boosted": self.is_boosted,
            "boost_active": self.is_boosted,
            "boost_timestamp": self.boost_timestamp,
            "silent_mode": self.silent_mode,
            "gaming_mode": self.silent_mode,
            "cpu_percent": cpu_pct,
            "ram": {
                "total_mb": ram_total_mb,
                "used_mb": ram_used_mb,
                "free_mb": round(mem.available / (1024 * 1024), 1),
                "percent": mem.percent
            },
            "ram_used_mb": ram_used_mb,
            "ram_total_mb": ram_total_mb,
            "ram_free_gb": ram_free_gb,
            "ram_percent": mem.percent,
            "power_plan": power_info.get("active_name", "Standard"),
            "current_scheme": power_info.get("active_name", "Standard"),
            "running_games": running_games,
            "active_games": running_games,
            "active_game_detected": len(running_games) > 0,
            "memory_freed_total_mb": round(self.memory_freed_total_mb, 1)
        }


# Global instance
game_optimizer = GameOptimizer()
