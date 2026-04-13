<div align="center">

# 🛡️ Veilguard

**Open-source endpoint security suite for Windows**

![Version](https://img.shields.io/badge/version-0.1.0--alpha-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![Stack](https://img.shields.io/badge/stack-Python%20%2B%20Rust-purple)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

</div>

---

## What is Veilguard?

Veilguard is a lightweight, open-source security suite that gives you full visibility into your system's network activity, open ports, running processes, and potential threats — all from a clean native desktop interface. Designed to grow from a powerful port scanner into a full endpoint virus guard.

> Built for security enthusiasts, developers, and privacy-conscious users who want to know exactly what their machine is doing.

---

## Features

| Module | Status | Description |
|--------|--------|-------------|
| Port Scanner | ✅ In development | Scan open ports, identify services, flag vulnerable endpoints |
| Process Monitor | ✅ In development | Live process list with active network connections |
| Threat Intelligence | 🔜 Planned | VirusTotal & Shodan API integration for IP/domain lookup |
| Firewall Control | 🔜 Planned | View and manage Windows firewall rules |
| Virus Guard | 🔜 Planned | Real-time file scanning with YARA rules & hash matching |
| Behaviour Engine | 🔜 Planned | Heuristic anomaly detection for suspicious processes |

---

## Tech Stack

- **UI** — Tauri (Rust) + React + TypeScript
- **Scanner engine** — Python 3.11+ with `python-nmap`, `psutil`, `scapy`
- **AV core** — Rust with YARA bindings and filesystem event watching
- **Database** — SQLite (local, encrypted with SQLCipher)
- **Threat APIs** — VirusTotal, Shodan, NVD CVE database

---

## Getting Started

> Prerequisites: Python 3.11+, Rust, Node.js 20 LTS, nmap installed

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/veilguard.git
cd veilguard

# Install Python dependencies
pip install -r requirements.txt

# Run the scanner engine
python src/scanner/port_scanner.py
```

_Full setup guide coming soon._

---

## Project Structure
