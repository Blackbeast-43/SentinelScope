# 🛡️ SentinelScope

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)
![Version](https://img.shields.io/badge/Version-1.0.0-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Security](https://img.shields.io/badge/Focus-Endpoint%20Security-red)

### Cross-Platform Endpoint Vulnerability & Threat Assessment Tool

**SentinelScope** is an open-source defensive cybersecurity tool written in Python for assessing the security posture of Windows and Linux endpoints.

It performs local system inspection, security misconfiguration checks, process analysis, network connection monitoring, persistence detection, and generates structured security assessment reports.

> Built for cybersecurity learning, defensive security research, endpoint assessment, and threat-hunting practice.

---

## 🔎 Overview

SentinelScope helps answer two important security questions:

1. **What security weaknesses or misconfigurations exist on this system?**
2. **Are there processes, network connections, or persistence mechanisms that deserve investigation?**

The tool performs multiple endpoint-security checks from a single interactive terminal interface.

SentinelScope does **not automatically classify a system as compromised**. Findings are security indicators that should be reviewed and validated by the analyst.

---

## ✨ Features

### 🖥️ System Information

Collects basic endpoint information including:

- Hostname
- Operating system
- OS release
- System architecture
- Python version
- CPU count
- Installed memory
- System boot time

---

### 🔐 Security & Misconfiguration Assessment

Checks the endpoint for security-related configuration issues such as:

- Host firewall status
- Potentially risky listening services
- Services exposed on all network interfaces
- FTP exposure
- Telnet exposure
- SMB exposure
- Remote Desktop exposure
- Database service exposure
- Redis exposure
- VNC exposure
- Elasticsearch exposure

### Linux-specific checks

- SSH root login configuration
- SSH password authentication

### Windows-specific checks

- SMBv1 status

---

## 🔬 Suspicious Process Analysis

SentinelScope examines running processes and identifies indicators that may require further investigation.

Examples include:

- Processes running from temporary directories
- Processes running from unusual locations
- Windows system process names running outside expected directories
- SHA-256 hashing of review-worthy executables
- PID and executable-path collection

Examples of locations that may receive additional scrutiny:

```text
Linux
/tmp/
/var/tmp/
/dev/shm/

Windows
AppData\Local\Temp
Windows\Temp
Users\Public
Downloads
```

A process running from one of these locations is **not automatically malicious**. SentinelScope reports it as an indicator for manual investigation.

---

## 🌐 Network Threat Analysis

Displays active network connections and maps them to local processes.

Information collected includes:

```text
Process
PID
Local Address
Remote Address
Connection Status
```

SentinelScope can also highlight connections using selected ports that may deserve additional investigation.

Example:

```text
Process          PID       Local                  Remote
----------------------------------------------------------------
chrome.exe       5412      192.168.1.10:51043     142.x.x.x:443
python.exe       8211      192.168.1.10:52120     10.x.x.x:4444
```

Port numbers alone are not treated as evidence of malicious activity.

---

## 🔁 Persistence & Startup Detection

SentinelScope inspects selected persistence and startup mechanisms.

### Windows

Currently checks:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run

HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

Startup entries referencing review-worthy locations can be highlighted.

### Linux

Currently checks:

```text
User crontab
~/.config/autostart/
```

Cron entries referencing locations such as `/tmp/` or `/dev/shm/` may be flagged for review.

---

## 📊 Security Reporting

A Full Security Assessment generates a JSON report containing the results of the scan.

Example:

```text
reports/sentinelscope_20261001_161522.json
```

Report data currently includes:

```text
System Information
Security Findings
Process Findings
Network Findings
Persistence Entries
Persistence Findings
Scan Date
Tool Version
```

Generated reports are excluded from Git tracking by default to help prevent endpoint information from accidentally being committed.

---

## 🖥️ Interactive Interface

When SentinelScope starts, the user is presented with an interactive menu:

```text
╭──────────────────────────────────────────────────────────╮
│                      SENTINELSCOPE                       │
│          Endpoint Vulnerability & Threat Assessment      │
│                                                          │
│                       Version 1.0.0                      │
│              Created by Adhithyan Saji Kumar             │
╰──────────────────────────────────────────────────────────╯


1. System Information

2. Vulnerability / Misconfiguration Scan

3. Suspicious Process Scan

4. Network Threat Scan

5. Persistence / Startup Scan

6. Full Security Assessment

7. About

0. Exit
```

---

# 🚀 Installation

## Linux

### 1. Clone the repository

```bash
git clone https://github.com/Blackbeast-43/SentinelScope.git
```

Enter the project directory:

```bash
cd SentinelScope
```

### 2. Create a Python virtual environment

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run SentinelScope

```bash
python3 sentinelscope.py
```

For additional visibility into system processes and network connections:

```bash
sudo ./venv/bin/python sentinelscope.py
```

---

# 🪟 Windows Installation

Make sure Python 3 is installed.

Clone the repository:

```powershell
git clone https://github.com/Blackbeast-43/SentinelScope.git
```

Move into the directory:

```powershell
cd SentinelScope
```

Create the virtual environment:

```powershell
python -m venv venv
```

Activate it:

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Start SentinelScope:

```powershell
python sentinelscope.py
```

For more complete system visibility, consider launching PowerShell using:

```text
Run as Administrator
```

before running SentinelScope.

---

# 📦 Requirements

SentinelScope currently uses:

```text
Python 3
psutil
rich
```

Install manually if necessary:

```bash
pip install psutil rich
```

---

# 📁 Project Structure

```text
SentinelScope/
│
├── sentinelscope.py
│
├── requirements.txt
│
├── README.md
│
├── LICENSE
│
├── .gitignore
│
└── reports/
    └── generated security reports
```

The `reports/` directory is excluded from Git using `.gitignore`.

---

# 🧪 Example Workflow

Launch SentinelScope:

```bash
python3 sentinelscope.py
```

Select:

```text
6. Full Security Assessment
```

SentinelScope will perform:

```text
System Information Collection
            ↓
Security Configuration Checks
            ↓
Listening Service Analysis
            ↓
Process Analysis
            ↓
Network Connection Analysis
            ↓
Persistence Analysis
            ↓
JSON Report Generation
```

---

# 🎯 Project Goals

SentinelScope is being developed as a practical cybersecurity project focusing on:

- Endpoint security
- Vulnerability assessment
- Threat hunting
- Security automation
- Windows security
- Linux security
- Network security
- Detection engineering
- Python development
- Security reporting

---

# 🛣️ Roadmap

## v1.0 ✅

- [x] Linux support
- [x] Windows support
- [x] Interactive CLI
- [x] System information collection
- [x] Firewall assessment
- [x] Listening-service analysis
- [x] Suspicious-process detection
- [x] SHA-256 hashing
- [x] Network connection analysis
- [x] Startup/persistence checks
- [x] JSON report generation

## v1.1

- [ ] Installed software inventory
- [ ] Software version detection
- [ ] CVE correlation
- [ ] CVSS severity display
- [ ] NVD vulnerability-data integration

## v1.2

- [ ] HTML security reports
- [ ] Improved risk-scoring engine
- [ ] Executive security summary
- [ ] Remediation recommendations

## v1.3

- [ ] File reputation analysis
- [ ] Digital-signature validation
- [ ] Improved executable analysis
- [ ] Threat-intelligence integration

## v1.4

- [ ] Windows Event Log analysis
- [ ] Linux authentication-log analysis
- [ ] Failed-login detection
- [ ] Security-event correlation

## v1.5

- [ ] Sigma detection-rule support
- [ ] Custom detection rules
- [ ] Detection-rule management

## v2.0

- [ ] Continuous endpoint monitoring
- [ ] Baseline creation
- [ ] Baseline comparison
- [ ] Security change detection
- [ ] Web dashboard

---

# ⚠️ Current Limitations

SentinelScope is currently an early-stage security project.

Version 1.0 does not currently:

- Exploit vulnerabilities
- Confirm exploitability of detected services
- Perform malware sandboxing
- Replace antivirus or EDR software
- Perform complete CVE correlation
- Guarantee that a suspicious indicator is malicious
- Guarantee that a system is free from compromise

Security findings should always be manually verified.

---

# 🔒 Privacy

SentinelScope performs its current assessment locally.

Generated security reports can contain sensitive information such as:

- Hostnames
- Process names
- IP addresses
- Open ports
- Startup entries
- Executable paths

For this reason, the `reports/` directory should **not be uploaded to a public repository**.

---

# ⚖️ Responsible Use

SentinelScope is intended for:

- Defensive cybersecurity
- Personal systems
- Cybersecurity laboratories
- Authorized security assessments
- Educational environments
- Security research

Only use security tools on systems that you own or have explicit permission to assess.

---

# 🤝 Contributions

Suggestions, bug reports, security improvements, and feature contributions are welcome.

Future development will focus on improving vulnerability detection, threat-hunting capabilities, security reporting, and cross-platform endpoint analysis.

---

# 👨‍💻 Author

**Blackbeast-43**

GitHub:

```text
https://github.com/Blackbeast-43
```

Project:

```text
https://github.com/Blackbeast-43/SentinelScope
```

---

# 📄 License

This project is intended to be released under the **MIT License**.

See the `LICENSE` file for details.

---

## ⭐ Support

If you find SentinelScope useful or interesting, consider giving the repository a **star**.

It helps support continued development of the project.

---

<p align="center">
  <b>SentinelScope</b><br>
  Endpoint Vulnerability & Threat Assessment Tool<br>
  Built with Python for Linux & Windows
</p>
