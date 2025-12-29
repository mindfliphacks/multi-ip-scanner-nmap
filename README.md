# 🛡️ APEX VANGUARD V10

**Cyber Intelligence & Network Reconnaissance Suite**

Apex Vanguard is a Flask-based web interface for Nmap that provides a futuristic "Cyber Ops" dashboard. It allows for batch scanning of targets, vulnerability detection, and automatic generation of PDF intelligence reports.

## 🚀 Features
* **Visual Dashboard:** Matrix-themed UI with real-time scanning feedback.
* **Batch Processing:** Queue multiple IP targets simultaneously.
* **Threat Intel:** automatically highlights vulnerabilities and open ports.
* **PDF Reporting:** Generates professional "Confidential" style PDF reports for every scan.
* **Modes:** Supports Standard, Aggressive, and Vulnerability (CVE) scanning profiles.

## 📦 Prerequisites

This tool requires **Nmap** to be installed on the host system.

**Debian/Kali/Ubuntu:**
```bash
sudo apt update
sudo apt install nmap
pip install fpdf2 
git clone https://github.com/mindfliphacks/multi-ip-scanner-nmap.git
cd multi-ip-scanner-nmap
python3 multi-ip-scanner.py

