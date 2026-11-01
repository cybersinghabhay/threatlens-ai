# 🛡️ ThreatLens AI

### AI-Ready Cybersecurity Investigation & Threat Analysis Toolkit

\<p align="center">
&#x20; \<strong>Detect. Analyze. Investigate. Understand.\</strong>
\</p>

\<p align="center">
&#x20; A cross-platform cybersecurity toolkit designed to help security enthusiasts and analysts investigate suspicious activity, monitor file integrity, analyze security logs, and generate structured investigation reports.
\</p>

\<p align="center">
&#x20; ![Python]\([https://img.shields.io/badge/Python-3.14+-blue?logo=python&logoColor=white](https://img.shields.io/badge/Python-3.14+-blue?logo=python\&logoColor=white))
&#x20; ![Platform]\([https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey))
&#x20; ![License]\([https://img.shields.io/badge/License-MIT-green](https://img.shields.io/badge/License-MIT-green))
&#x20; ![Tests]\([https://img.shields.io/badge/Tests-116%20Passing-brightgreen](https://img.shields.io/badge/Tests-116%20Passing-brightgreen))
&#x20; ![Status]\([https://img.shields.io/badge/Project-Active%20Development-orange](https://img.shields.io/badge/Project-Active%20Development-orange))
\</p>

---

## 🔍 About the Project

**ThreatLens AI** is a modular cybersecurity investigation toolkit that brings together file integrity monitoring, security log analysis, suspicious activity detection, and investigation reporting.

The project aims to make security analysis more accessible by combining traditional security detection techniques with an architecture designed for future AI-assisted investigation.

Instead of simply identifying suspicious events, ThreatLens AI focuses on organizing security evidence, assigning initial severity levels, explaining findings, and presenting investigation results in readable reports.

**Current detection capabilities are rule-based. AI-assisted analysis and threat intelligence integrations are part of the development roadmap.**

## ⚡ Core Capabilities

| Module                    | Capabilities                                                                |
| ------------------------- | --------------------------------------------------------------------------- |
| 🔐 File Integrity         | SHA-256 hashing, baseline creation, modification detection                  |
| 📁 Directory Monitoring   | Recursive file monitoring and change detection                              |
| 📊 Security Log Analysis  | Failed login, successful login, warning, error and critical event detection |
| 🚨 Threat Detection       | Repeated failed-login detection and severity classification                 |
| 🎯 Severity Filtering     | Filter security events and findings by severity                             |
| 🧠 Finding Explainer      | Rule-based explanations and recommended actions                             |
| 🕒 Investigation Timeline | Chronological ordering of security events                                   |
| 📄 JSON Reports           | Structured investigation report generation                                  |
| 🌐 HTML Dashboard         | Browser-readable security reports and interactive severity filtering        |

## 🏗️ Project Architecture

```text
ThreatLens AI
│
├── File Integrity Monitoring
│   ├── SHA-256 Hashing
│   ├── Baseline Management
│   └── Directory Integrity
│
├── Security Log Analysis
│   ├── Event Detection
│   ├── Failed Login Analysis
│   ├── Warning / Error / Critical Events
│   └── Timestamp Extraction
│
├── Investigation Engine
│   ├── Severity Classification
│   ├── Severity Filtering
│   ├── Finding Explanations
│   └── Investigation Timeline
│
└── Reporting Engine
    ├── JSON Reports
    └── HTML Security Dashboard
```

## 🖥️ Technology Stack

- **Language:** Python
- **Testing:** Pytest
- **Security:** SHA-256, log analysis, file integrity monitoring
- **Reporting:** JSON, HTML, CSS, JavaScript
- **Development:** VS Code, Git, GitHub
- **Platforms:** Windows and Linux

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/cybersinghabhay/threatlens-ai.git
```

### 2. Navigate to the project directory

```bash
cd threatlens-ai
```

### 3. Create a virtual environment

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install the project

```bash
python -m pip install -e .
```

### 5. Run ThreatLens AI

```bash
python -m threatlens_ai.main
```

## 🧪 Testing

ThreatLens AI uses Pytest for automated testing.

Run the complete test suite:

```bash
python -m pytest -v
```

The project currently has **116 passing tests**.

## 🗺️ Development Roadmap

ThreatLens AI is actively evolving.

- [x] SHA-256 file integrity monitoring
- [x] File integrity baseline validation
- [x] Directory integrity monitoring
- [x] Security log analysis
- [x] Repeated failed-login detection
- [x] JSON investigation reports
- [x] HTML security dashboard
- [x] Rule-based finding explanations
- [x] Investigation timeline
- [x] Security event severity classification
- [x] Interactive severity filtering
- [ ] IP address intelligence and classification
- [ ] Threat intelligence API integration
- [ ] AI-assisted security finding analysis
- [ ] Local AI model integration
- [ ] Advanced investigation correlation
- [ ] Expanded automated security testing

## 🔒 Security & Privacy Principles

Security and privacy are important design considerations.

- Avoid exposing credentials, API keys, and sensitive log data.
- Use synthetic security logs for development and testing.
- Classify private, loopback, and reserved IP addresses before external enrichment.
- Keep detection logic separate from AI-generated explanations.
- Preserve original investigation evidence when applying filters.
- Treat automated findings as indicators requiring human verification.

## 🎯 Project Vision

The long-term goal is to evolve ThreatLens AI into a modular cybersecurity investigation platform that combines:

- Traditional security monitoring and detection.
- Threat intelligence and contextual enrichment.
- AI-assisted investigation and finding explanations.
- Local and hosted AI model support.
- Structured, evidence-based security reporting.

## 🤝 Contributions

Suggestions, feature requests, and improvements are welcome.

If you find an issue or have an idea, feel free to open a GitHub issue.

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

\<p align="center">
&#x20; \<strong>ThreatLens AI — Bringing clarity to cybersecurity investigations.\</strong>
\</p>

\<p align="center">
&#x20; Built with Python, cybersecurity knowledge, and a vision for AI-assisted security.
\</p>
