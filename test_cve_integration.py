#!/usr/bin/env python3
"""Test script for CVE integration"""

from src.scanner.threat_lookup import CVELookup

def test_cve_lookup():
    print("Testing CVE Lookup Integration...\n")
    
    cve_lookup = CVELookup()
    
    # Test 1: Search by service name
    print("=" * 60)
    print("Test 1: Searching for OpenSSH CVEs...")
    print("=" * 60)
    cves = cve_lookup.search_by_keyword("OpenSSH")
    
    if cves:
        print(f"Found {len(cves)} CVEs for OpenSSH\n")
        for i, cve in enumerate(cves[:3], 1):  # Show first 3
            print(f"{i}. {cve['cve_id']}")
            print(f"   CVSS Score: {cve['cvss_score']}")
            print(f"   Published: {cve['published']}")
            print(f"   Description: {cve['description'][:100]}...")
            print(f"   URL: {cve['url']}\n")
    else:
        print("No CVEs found (API may be rate limited or unavailable)\n")
    
    # Test 2: Search Apache
    print("=" * 60)
    print("Test 2: Searching for Apache CVEs...")
    print("=" * 60)
    cves = cve_lookup.search_by_keyword("Apache")
    
    if cves:
        print(f"Found {len(cves)} CVEs for Apache\n")
        for i, cve in enumerate(cves[:3], 1):
            print(f"{i}. {cve['cve_id']}")
            print(f"   CVSS Score: {cve['cvss_score']}")
            print(f"   URL: {cve['url']}\n")
    else:
        print("No CVEs found\n")
    
    print("=" * 60)
    print("CVE Lookup Test Complete!")
    print("=" * 60)

if __name__ == "__main__":
    test_cve_lookup()
