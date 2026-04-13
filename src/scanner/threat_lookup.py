import requests
import os
from rich.console import Console
import time

console = Console()

VIRUSTOTAL_API = "https://www.virustotal.com/api/v3/ip_addresses"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVELookup:
    """Query the NVD (National Vulnerability Database) for CVEs"""
    
    def __init__(self):
        self.base_url = NVD_API
        self.cache = {}
        self.last_request_time = 0
        self.min_request_interval = 0.6  # NVD API rate limit: ~6 requests per 30 seconds
    
    def _rate_limit(self):
        """Respect NVD API rate limits"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()
    
    def search_by_keyword(self, keyword: str) -> list:
        """Search NVD for CVEs by keyword (service name, product, etc.)"""
        if keyword in self.cache:
            return self.cache[keyword]
        
        try:
            self._rate_limit()
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 20
            }
            response = requests.get(self.base_url, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            results = []
            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                results.append({
                    "cve_id": cve_data.get("id", "N/A"),
                    "description": cve_data.get("descriptions", [{}])[0].get("value", "N/A"),
                    "cvss_score": self._extract_cvss_score(cve_data),
                    "published": cve_data.get("published", "N/A"),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_data.get('id', 'N/A')}"
                })
            
            self.cache[keyword] = results
            return results
        except Exception as e:
            console.print(f"[dim]CVE lookup error for '{keyword}': {e}[/dim]")
            return []
    
    def _extract_cvss_score(self, cve_data: dict) -> str:
        """Extract CVSS score from CVE data (v3.1 preferred, fallback to v3.0)"""
        metrics = cve_data.get("metrics", {})
        
        # Try CVSS v3.1
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            score = cvss_v31[0].get("cvssData", {}).get("baseScore", "N/A")
            return f"{score} (v3.1)"
        
        # Try CVSS v3.0
        cvss_v30 = metrics.get("cvssMetricV30", [])
        if cvss_v30:
            score = cvss_v30[0].get("cvssData", {}).get("baseScore", "N/A")
            return f"{score} (v3.0)"
        
        # Try CVSS v2.0
        cvss_v2 = metrics.get("cvssMetricV2", [])
        if cvss_v2:
            score = cvss_v2[0].get("cvssData", {}).get("baseScore", "N/A")
            return f"{score} (v2.0)"
        
        return "N/A"
    
    def search_by_cpe(self, cpe: str) -> list:
        """Search NVD for CVEs by CPE (Common Platform Enumeration)"""
        if cpe in self.cache:
            return self.cache[cpe]
        
        try:
            self._rate_limit()
            params = {
                "cpeName": cpe,
                "resultsPerPage": 20
            }
            response = requests.get(self.base_url, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            results = []
            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                results.append({
                    "cve_id": cve_data.get("id", "N/A"),
                    "description": cve_data.get("descriptions", [{}])[0].get("value", "N/A"),
                    "cvss_score": self._extract_cvss_score(cve_data),
                    "published": cve_data.get("published", "N/A"),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_data.get('id', 'N/A')}"
                })
            
            self.cache[cpe] = results
            return results
        except Exception as e:
            console.print(f"[dim]CVE lookup error for '{cpe}': {e}[/dim]")
            return []


class ThreatLookup:
    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "")

    def lookup_ip(self, ip: str) -> dict:
        if not self.api_key:
            return {"error": "No VirusTotal API key set in .env"}

        try:
            headers = {"x-apikey": self.api_key}
            response = requests.get(
                f"{VIRUSTOTAL_API}/{ip}",
                headers=headers,
                timeout=10
            )
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "ip": ip,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
            }
        except Exception as e:
            return {"error": str(e)}


class GeoIPLookup:
    """Query ip-api.com for geolocation and reverse DNS information"""
    
    HIGH_RISK_COUNTRIES = {
        "CN": "China",
        "RU": "Russia",
        "IR": "Iran",
        "KP": "North Korea",
        "SY": "Syria",
    }
    
    def __init__(self):
        self.base_url = "http://ip-api.com/json"
        self.cache = {}
    
    def lookup(self, ip: str) -> dict:
        """
        Lookup geolocation data for an IP address.
        Returns country, city, ISP, organization, and risk assessment.
        """
        if ip in self.cache:
            return self.cache[ip]
        
        # Skip private IPs (localhost, 192.168.x.x, 10.x.x.x, 172.16-31.x.x)
        if self._is_private_ip(ip):
            result = {
                "ip": ip,
                "country": "Private Network",
                "country_code": "PRIVATE",
                "city": "N/A",
                "isp": "N/A",
                "org": "N/A",
                "is_high_risk": False,
                "is_private": True,
                "latitude": None,
                "longitude": None,
            }
            self.cache[ip] = result
            return result
        
        try:
            params = {
                "query": ip,
                "fields": "status,country,countryCode,city,isp,org,lat,lon,reverse"
            }
            response = requests.get(self.base_url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get("status") == "fail":
                return {"error": f"Could not lookup IP: {ip}"}
            
            country_code = data.get("countryCode", "")
            is_high_risk = country_code in self.HIGH_RISK_COUNTRIES
            
            result = {
                "ip": ip,
                "country": data.get("country", "Unknown"),
                "country_code": country_code,
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "org": data.get("org", "Unknown"),
                "is_high_risk": is_high_risk,
                "is_private": False,
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "reverse_dns": data.get("reverse", "N/A"),
            }
            
            self.cache[ip] = result
            return result
            
        except Exception as e:
            console.print(f"[dim]GeoIP lookup error for '{ip}': {e}[/dim]")
            return {"error": str(e), "ip": ip}
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private/reserved ranges"""
        try:
            parts = [int(x) for x in ip.split(".")]
            if len(parts) != 4:
                return False
            
            # Localhost
            if parts[0] == 127:
                return True
            # Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            # Link-local: 169.254.0.0/16
            if parts[0] == 169 and parts[1] == 254:
                return True
            
            return False
        except:
            return False
    
    def reverse_dns(self, ip: str) -> str:
        """Get reverse DNS name for IP"""
        try:
            import socket
            return socket.gethostbyaddr(ip)[0]
        except:
            return "N/A"