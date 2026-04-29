"""
Veilguard — Threat Intelligence Module
Handles: VirusTotal IP lookup, NVD CVE lookup, GeoIP lookup

NEW in this version:
  - VirusTotal lookup now has a proper cache (avoids burning API quota)
  - VirusTotal rate limiter (free tier = 4 requests/minute)
  - lookup_ip() returns richer data: owner, country, verdict label
  - GeoIPLookup unchanged but re-exported for convenience
"""

import requests
import os
import time
import socket
from rich.console import Console

console = Console()

VIRUSTOTAL_IP_API = "https://www.virustotal.com/api/v3/ip_addresses"
NVD_API           = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ---------------------------------------------------------------------------
# CVE Lookup
# ---------------------------------------------------------------------------

class CVELookup:
    """Query the NVD (National Vulnerability Database) for CVEs."""

    def __init__(self):
        self.base_url             = NVD_API
        self.cache                = {}
        self.last_request_time    = 0
        self.min_request_interval = 0.6   # NVD rate limit: ~6 req / 30 s

    def _rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()

    def search_by_keyword(self, keyword: str) -> list:
        if keyword in self.cache:
            return self.cache[keyword]
        try:
            self._rate_limit()
            response = requests.get(
                self.base_url,
                params={"keywordSearch": keyword, "resultsPerPage": 20},
                timeout=15
            )
            response.raise_for_status()
            vulnerabilities = response.json().get("vulnerabilities", [])
            results = [self._parse_vuln(v) for v in vulnerabilities]
            self.cache[keyword] = results
            return results
        except Exception as e:
            console.print(f"[dim]CVE lookup error for '{keyword}': {e}[/dim]")
            return []

    def search_by_cpe(self, cpe: str) -> list:
        if cpe in self.cache:
            return self.cache[cpe]
        try:
            self._rate_limit()
            response = requests.get(
                self.base_url,
                params={"cpeName": cpe, "resultsPerPage": 20},
                timeout=15
            )
            response.raise_for_status()
            vulnerabilities = response.json().get("vulnerabilities", [])
            results = [self._parse_vuln(v) for v in vulnerabilities]
            self.cache[cpe] = results
            return results
        except Exception as e:
            console.print(f"[dim]CVE lookup error for '{cpe}': {e}[/dim]")
            return []

    def _parse_vuln(self, vuln: dict) -> dict:
        cve_data = vuln.get("cve", {})
        return {
            "cve_id":      cve_data.get("id", "N/A"),
            "description": (cve_data.get("descriptions") or [{}])[0].get("value", "N/A"),
            "cvss_score":  self._extract_cvss_score(cve_data),
            "published":   cve_data.get("published", "N/A"),
            "url":         f"https://nvd.nist.gov/vuln/detail/{cve_data.get('id','N/A')}",
        }

    def _extract_cvss_score(self, cve_data: dict) -> str:
        metrics = cve_data.get("metrics", {})
        for key, label in [
            ("cvssMetricV31", "v3.1"),
            ("cvssMetricV30", "v3.0"),
            ("cvssMetricV2",  "v2.0"),
        ]:
            entries = metrics.get(key, [])
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore", "N/A")
                return f"{score} ({label})"
        return "N/A"


# ---------------------------------------------------------------------------
# VirusTotal IP Lookup  ← enhanced
# ---------------------------------------------------------------------------

class ThreatLookup:
    """
    Check IP addresses against VirusTotal.

    Free tier limits: 4 requests per minute, 500 per day.
    We protect against both with a rate limiter and an in-memory cache.
    The cache persists for the lifetime of the process — restarting clears it.
    """

    # Verdict thresholds
    MALICIOUS_THRESHOLD  = 1   # ≥ 1 engine flags → malicious
    SUSPICIOUS_THRESHOLD = 3   # ≥ 3 engines flag → suspicious

    def __init__(self):
        self.api_key           = os.getenv("VIRUSTOTAL_API_KEY", "")
        self._cache: dict      = {}           # ip → result dict
        self._last_call: float = 0.0
        self._min_interval     = 15.0         # 4 req/min = 1 per 15 s

    # --- public API -------------------------------------------------------

    def lookup_ip(self, ip: str) -> dict:
        """
        Look up an IP on VirusTotal.

        Returns a dict with keys:
          ip, malicious, suspicious, harmless, undetected,
          reputation, owner, country, verdict, verdict_label, cached
        On error returns {"error": "...", "ip": ip}
        """
        if not self.api_key:
            return {"error": "No VIRUSTOTAL_API_KEY in .env", "ip": ip}

        if ip in self._cache:
            result = dict(self._cache[ip])
            result["cached"] = True
            return result

        self._rate_limit()

        try:
            headers  = {"x-apikey": self.api_key}
            response = requests.get(
                f"{VIRUSTOTAL_IP_API}/{ip}",
                headers=headers,
                timeout=12
            )

            if response.status_code == 404:
                return {"error": "IP not found in VirusTotal", "ip": ip}
            if response.status_code == 429:
                return {"error": "VirusTotal rate limit hit — slow down", "ip": ip}

            response.raise_for_status()
            data  = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious   = stats.get("malicious",   0)
            suspicious  = stats.get("suspicious",  0)
            harmless    = stats.get("harmless",    0)
            undetected  = stats.get("undetected",  0)
            reputation  = attrs.get("reputation",  0)
            owner       = attrs.get("as_owner",    "Unknown")
            country     = attrs.get("country",     "Unknown")

            # Compute a simple verdict
            if malicious >= self.MALICIOUS_THRESHOLD:
                verdict       = "malicious"
                verdict_label = f"MALICIOUS ({malicious} engines)"
            elif suspicious >= self.SUSPICIOUS_THRESHOLD:
                verdict       = "suspicious"
                verdict_label = f"SUSPICIOUS ({suspicious} engines)"
            elif reputation < -10:
                verdict       = "suspicious"
                verdict_label = f"LOW REPUTATION ({reputation})"
            else:
                verdict       = "clean"
                verdict_label = "Clean"

            result = {
                "ip":           ip,
                "malicious":    malicious,
                "suspicious":   suspicious,
                "harmless":     harmless,
                "undetected":   undetected,
                "reputation":   reputation,
                "owner":        owner,
                "country":      country,
                "verdict":      verdict,       # "malicious" | "suspicious" | "clean"
                "verdict_label": verdict_label,
                "cached":       False,
            }

            self._cache[ip] = result
            return result

        except Exception as e:
            return {"error": str(e), "ip": ip}

    def is_malicious(self, ip: str) -> bool:
        """Quick boolean check — uses cache, no extra API call if already looked up."""
        cached = self._cache.get(ip)
        if cached:
            return cached.get("verdict") in ("malicious", "suspicious")
        return False

    def bulk_lookup(self, ips: list) -> dict:
        """
        Look up multiple IPs, respecting rate limits.
        Returns {ip: result_dict, ...}
        Skips private IPs automatically.
        """
        results = {}
        for ip in ips:
            if GeoIPLookup._is_private_ip_static(ip):
                continue
            results[ip] = self.lookup_ip(ip)
        return results

    # --- internals --------------------------------------------------------

    def _rate_limit(self):
        elapsed = time.time() - self._last_call
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_call = time.time()


# ---------------------------------------------------------------------------
# GeoIP Lookup  ← unchanged, added _is_private_ip_static classmethod
# ---------------------------------------------------------------------------

class GeoIPLookup:
    """Query ip-api.com for geolocation and reverse DNS (free, no key needed)."""

    HIGH_RISK_COUNTRIES = {
        "CN": "China",
        "RU": "Russia",
        "IR": "Iran",
        "KP": "North Korea",
        "SY": "Syria",
    }

    def __init__(self):
        self.base_url = "http://ip-api.com/json"
        self.cache    = {}

    def lookup(self, ip: str) -> dict:
        if ip in self.cache:
            return self.cache[ip]

        if self._is_private_ip(ip):
            result = {
                "ip": ip, "country": "Private Network",
                "country_code": "PRIVATE", "city": "N/A",
                "isp": "N/A", "org": "N/A",
                "is_high_risk": False, "is_private": True,
                "latitude": None, "longitude": None,
                "reverse_dns": "N/A", "flag": "",
            }
            self.cache[ip] = result
            return result

        try:
            response = requests.get(
                f"{self.base_url}/{ip}",
                params={"fields": "status,country,countryCode,city,isp,org,lat,lon,reverse"},
                timeout=8
            )
            response.raise_for_status()
            data = response.json()

            if data.get("status") == "fail":
                return {"error": f"Could not lookup IP: {ip}", "ip": ip}

            country_code = data.get("countryCode", "")
            is_high_risk = country_code in self.HIGH_RISK_COUNTRIES

            # Build a country flag emoji from the country code
            # Each letter A-Z maps to a regional indicator symbol A🇦 … Z🇿
            flag = ""
            if len(country_code) == 2:
                flag = "".join(
                    chr(0x1F1E6 + ord(c) - ord('A'))
                    for c in country_code.upper()
                )

            result = {
                "ip":           ip,
                "country":      data.get("country",     "Unknown"),
                "country_code": country_code,
                "city":         data.get("city",        "Unknown"),
                "isp":          data.get("isp",         "Unknown"),
                "org":          data.get("org",         "Unknown"),
                "is_high_risk": is_high_risk,
                "is_private":   False,
                "latitude":     data.get("lat"),
                "longitude":    data.get("lon"),
                "reverse_dns":  data.get("reverse", "N/A"),
                "flag":         flag,
            }
            self.cache[ip] = result
            return result

        except Exception as e:
            console.print(f"[dim]GeoIP lookup error for '{ip}': {e}[/dim]")
            return {"error": str(e), "ip": ip}

    # static version so ThreatLookup.bulk_lookup can use it without instantiation
    @staticmethod
    def _is_private_ip_static(ip: str) -> bool:
        return GeoIPLookup._check_private(ip)

    def _is_private_ip(self, ip: str) -> bool:
        return GeoIPLookup._check_private(ip)

    @staticmethod
    def _check_private(ip: str) -> bool:
        try:
            parts = [int(x) for x in ip.split(".")]
            if len(parts) != 4:
                return False
            a, b = parts[0], parts[1]
            if a == 127:               return True   # loopback
            if a == 10:                return True   # 10/8
            if a == 172 and 16 <= b <= 31: return True  # 172.16/12
            if a == 192 and b == 168:  return True   # 192.168/16
            if a == 169 and b == 254:  return True   # link-local
            return False
        except Exception:
            return False

    def reverse_dns(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "N/A"
