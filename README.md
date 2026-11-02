# 🛡️ ThreatLens AI

### AI-Ready Cybersecurity Investigation & Threat Analysis Toolkit

<p align="center">
  <strong>Detect. Analyze. Investigate. Understand.</strong>
</p>

<p align="center">
  A modular, cross-platform cybersecurity toolkit for file integrity monitoring, security log analysis, suspicious activity detection, and structured digital investigations.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.14-blue?logo=python&logoColor=white" alt="Python 3.14">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue" alt="Windows and Linux">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/Tests-116%20Passing-brightgreen" alt="116 passing tests">
  <img src="https://img.shields.io/badge/Status-Active%20Development-orange" alt="Active development">
</p>

---


---

## 🔍 Overview

**ThreatLens AI** is a cybersecurity investigation toolkit developed to bring essential security analysis capabilities together in one modular Python application.

It focuses on identifying suspicious activity, monitoring file and directory integrity, analyzing security logs, organizing investigation evidence, and generating structured security reports.

The project combines traditional rule-based detection with an architecture designed to support future AI-assisted investigation and threat intelligence capabilities.

Rather than simply reporting suspicious events, ThreatLens AI aims to help users understand what happened, examine relevant evidence, assess initial severity, and communicate findings through readable reports.

> **Current implementation:** Detection and finding explanations are rule-based. AI-powered analysis and external threat intelligence integrations are planned development milestones.

## ⚡ Key Features

| Module | Functionality |
|---|---|
| 🔐 File Integrity Monitoring | SHA-256 hashing, baseline creation, and file modification detection |
| 📁 Directory Integrity Monitoring | Recursive directory scanning and added, modified, and deleted file detection |
| 📊 Security Log Analyzer | Detection of failed logins, successful logins, warnings, errors, and critical events |
| 🚨 Suspicious Activity Detection | Identification of repeated failed login attempts |
| 🎯 Severity Classification | Initial severity assignment to detected security events and findings |
| 🔎 Severity Filtering | Filter events and findings by severity without modifying original evidence |
| 🧠 Finding Explainer | Rule-based explanations and recommended actions |
| 🕒 Investigation Timeline | Chronological organization of security events |
| 📄 JSON Reporting | Structured investigation reports for further processing |
| 🌐 HTML Security Dashboard | Browser-readable reports with interactive severity filtering |

## 🏗️ Architecture

ThreatLens AI follows a modular architecture that separates detection, investigation, and reporting responsibilities.

```text
ThreatLens AI
│
├── File Integrity Module
│   ├── SHA-256 Hashing
│   ├── Baseline Management
│   └── Directory Integrity Monitoring
│
├── Security Log Analysis
│   ├── Log Event Detection
│   ├── Failed Login Analysis
│   ├── Successful Login Detection
│   ├── Warning / Error / Critical Events
│   └── Timestamp Extraction
│
├── Investigation Engine
│   ├── Severity Classification
│   ├── Severity Filtering
│   ├── Finding Explanations
│   └── Chronological Timeline
│
└── Reporting Engine
    ├── JSON Reports
    └── HTML Security Dashboard
```

### Design Principles

- **Modularity:** Keep individual security capabilities independent and maintainable.
- **Evidence preservation:** Filtering and presentation should not modify original investigation evidence.
- **Separation of concerns:** Keep detection, severity classification, and explanations separate.
- **Cross-platform compatibility:** Design for Windows and Linux.
- **Privacy awareness:** Avoid unnecessary exposure of sensitive information.
- **Human verification:** Treat automated findings as investigation indicators, not definitive proof of an attack.

## 🖥️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application development |
| Pytest | Automated testing |
| SHA-256 | File integrity verification |
| JSON | Structured report generation |
| HTML / CSS | Security report presentation |
| JavaScript | Interactive HTML dashboard filtering |
| Git & GitHub | Version control and project collaboration |
| VS Code | Development environment |

## 🚀 Installation & Setup

### Prerequisites

- Python 3.14 (the current development environment)
- Git
- Windows or Linux
- Terminal or PowerShell

### 1. Clone the repository

```bash
git clone https://github.com/cybersinghabhay/threatlens-ai.git
```

### 2. Navigate to the project directory

```bash
cd threatlens-ai
```

### 3. Create a virtual environment

**Windows — PowerShell**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install the project

```bash
python -m pip install -e .
```

### 5. Launch ThreatLens AI

```bash
python -m threatlens_ai.main
```

## 🧪 Testing

ThreatLens AI uses **Pytest** to validate its modules and help maintain application reliability.

Run the complete test suite:

```bash
python -m pytest -v
```

<details>
<summary><strong>Current testing status</strong></summary>

The latest recorded complete test run reported:

- **116 tests passed**
- No failing tests in that run.

Test coverage includes file integrity, directory monitoring, log analysis, severity filtering, investigation timelines, and report generation.

</details>

## 🗺️ Development Roadmap

ThreatLens AI is actively evolving. The roadmap reflects completed functionality and planned development.

### Completed

- [x] SHA-256 file integrity monitoring
- [x] File integrity baseline validation
- [x] Structured file integrity reports
- [x] Directory integrity monitoring
- [x] Added, modified, and deleted file detection
- [x] Security log analysis
- [x] Repeated failed-login detection
- [x] Successful login event detection
- [x] Warning, error, and critical event collection
- [x] Timestamp extraction
- [x] JSON security reports
- [x] HTML security dashboard
- [x] Rule-based finding explanations
- [x] Chronological investigation timeline
- [x] Security event severity classification
- [x] Interactive severity filtering

### Planned

- [ ] IP address validation and classification
- [ ] Threat intelligence API integration
- [ ] AI-assisted security finding analysis
- [ ] Local AI model integration
- [ ] Hosted AI model support
- [ ] Advanced event correlation
- [ ] Enhanced investigation workflows
- [ ] Expanded automated testing and documentation

## 🔒 Security & Privacy

Security and privacy are important considerations throughout ThreatLens AI development.

The project follows these principles:

- Never expose passwords, credentials, API keys, or authentication tokens in reports or source control.
- Prefer synthetic security logs for development and testing.
- Validate IP addresses before performing threat intelligence enrichment.
- Avoid unnecessarily transmitting private, loopback, or reserved IP addresses to external services.
- Keep security detection independent of AI-generated explanations.
- Preserve original evidence when filtering or presenting findings.
- Require human verification before treating automated findings as confirmed malicious activity.

## 🎯 Long-Term Vision

The vision is to evolve ThreatLens AI into a modular, AI-assisted cybersecurity investigation platform.

Future development will focus on combining:

- Traditional security monitoring and detection.
- IP intelligence and threat context enrichment.
- AI-assisted investigation and finding explanations.
- Local and hosted AI model integration.
- Investigation correlation and evidence analysis.
- Structured, evidence-based reporting.

The goal is to build a practical toolkit that demonstrates the intersection of **Cybersecurity, Digital Investigation, Python Development, and Artificial Intelligence**.

## 🤝 Contributions

Suggestions, bug reports, feature requests, and improvements are welcome.

If you discover an issue or have an idea for improving ThreatLens AI, feel free to open a GitHub Issue.

## 📜 License

ThreatLens AI is released under the [MIT License](LICENSE).

---

<p align="center">

**ThreatLens AI — Bringing clarity to cybersecurity investigations.**

Built with Python, cybersecurity knowledge, and a vision for AI-assisted security.

</p>
