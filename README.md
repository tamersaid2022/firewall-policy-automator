<div align="center">

# 🔥 Firewall Policy Automator

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Palo Alto](https://img.shields.io/badge/Palo_Alto-PAN--OS-F04E23?style=for-the-badge&logo=paloaltonetworks&logoColor=white)](https://paloaltonetworks.com)
[![FortiGate](https://img.shields.io/badge/FortiGate-FortiOS-EE3124?style=for-the-badge&logo=fortinet&logoColor=white)](https://fortinet.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**Enterprise-grade firewall policy automation for Palo Alto and FortiGate platforms**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Examples](#-examples) • [Documentation](#-documentation)

---

<img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/python/python-original.svg" width="60" height="60" alt="Python"/>
&nbsp;&nbsp;&nbsp;
<img src="https://www.vectorlogo.zone/logos/paloaborete/paloaborete-icon.svg" width="60" height="60" alt="Palo Alto"/>

</div>

## 🎯 Overview

The **Firewall Policy Automator** eliminates manual firewall rule management by providing a Python-based solution for automated policy deployment, validation, and compliance checking across multi-vendor environments.

### Key Capabilities

| Feature | Description |
|---------|-------------|
| 🔄 **Multi-Vendor Support** | Unified API for Palo Alto PAN-OS and FortiGate FortiOS |
| 📝 **Policy as Code** | Define firewall rules in YAML/JSON format |
| ✅ **Pre-deployment Validation** | Syntax checking, conflict detection, shadowed rule analysis |
| 📊 **Compliance Reporting** | Generate audit-ready compliance reports |
| 🔙 **Rollback Support** | Automatic backup and one-click rollback |
| 📈 **Bulk Operations** | Deploy hundreds of rules in seconds |

---

## ⚡ Features

### 🛡️ Supported Platforms

```
┌─────────────────────────────────────────────────────────────┐
│  PALO ALTO NETWORKS           │  FORTINET                   │
├─────────────────────────────────────────────────────────────┤
│  • PAN-OS 9.x, 10.x, 11.x     │  • FortiOS 6.x, 7.x        │
│  • Panorama (Device Groups)    │  • FortiManager Support     │
│  • VM-Series, PA-Series        │  • Virtual & Hardware       │
│  • XML API & REST API          │  • REST API                 │
└─────────────────────────────────────────────────────────────┘
```

### 🔧 Core Functions

- **Create** - Deploy new security policies from templates
- **Read** - Export existing policies to YAML/JSON/CSV
- **Update** - Modify rules with change tracking
- **Delete** - Safe removal with dependency checking
- **Validate** - Pre-flight checks before deployment
- **Audit** - Compliance verification against baselines

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/tamersaid2022/firewall-policy-automator.git
cd firewall-policy-automator

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

### Requirements

```txt
pan-os-python>=1.8.0
requests>=2.28.0
pyyaml>=6.0
jinja2>=3.1.0
rich>=13.0.0
python-dotenv>=1.0.0
```

---

## 🚀 Usage

### Quick Start

```python
from firewall_automator import FirewallAutomator

# Initialize connection
fw = FirewallAutomator(
    platform="paloalto",
    host="192.168.1.1",
    api_key="your-api-key"
)

# Deploy policy from YAML
fw.deploy_policy("policies/web-server-rules.yaml")

# Validate before commit
if fw.validate():
    fw.commit()
```

### Command Line Interface

```bash
# Deploy policies
python firewall_automator.py deploy --config policies/production.yaml

# Export current rules
python firewall_automator.py export --format yaml --output backup/

# Validate configuration
python firewall_automator.py validate --config policies/new-rules.yaml

# Generate compliance report
python firewall_automator.py audit --baseline compliance/pci-dss.yaml
```

---

## 📋 Examples

### Policy Definition (YAML)

```yaml
# policies/web-server-rules.yaml
---
policy_name: "Web-Server-Access"
description: "Allow HTTPS traffic to web servers"
rules:
  - name: "Allow-HTTPS-Inbound"
    source_zone: "untrust"
    destination_zone: "dmz"
    source_ip: ["any"]
    destination_ip: ["10.10.10.0/24"]
    application: ["ssl", "web-browsing"]
    service: ["application-default"]
    action: "allow"
    log_end: true
    profile_group: "strict-security"
    
  - name: "Allow-Web-to-DB"
    source_zone: "dmz"
    destination_zone: "trust"
    source_ip: ["10.10.10.0/24"]
    destination_ip: ["10.20.20.0/24"]
    application: ["mysql", "postgresql"]
    service: ["application-default"]
    action: "allow"
    log_end: true
```

### Bulk Deployment Script

```python
from firewall_automator import FirewallAutomator
from pathlib import Path

# Connect to Panorama
panorama = FirewallAutomator(
    platform="panorama",
    host="panorama.company.com",
    api_key=os.getenv("PAN_API_KEY")
)

# Deploy to multiple device groups
device_groups = ["DC-East", "DC-West", "Branch-Offices"]
policy_file = "policies/corporate-standard.yaml"

for dg in device_groups:
    print(f"Deploying to {dg}...")
    panorama.deploy_policy(policy_file, device_group=dg)
    
# Validate all changes
validation = panorama.validate_all()
if validation.success:
    panorama.commit_all(device_groups)
    print("✅ Deployment successful!")
else:
    print(f"❌ Validation failed: {validation.errors}")
    panorama.rollback()
```

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║           FIREWALL POLICY DEPLOYMENT REPORT                  ║
╠══════════════════════════════════════════════════════════════╣
║  Target:     PA-5260 (192.168.1.1)                          ║
║  Policy:     Web-Server-Access                               ║
║  Rules:      12 rules processed                              ║
║  Status:     ✅ SUCCESS                                      ║
╠══════════════════════════════════════════════════════════════╣
║  VALIDATION RESULTS                                          ║
║  ├─ Syntax Check:        ✅ PASSED                          ║
║  ├─ Conflict Detection:  ✅ NO CONFLICTS                    ║
║  ├─ Shadow Analysis:     ⚠️  2 WARNINGS                     ║
║  └─ Compliance Check:    ✅ PCI-DSS COMPLIANT               ║
╠══════════════════════════════════════════════════════════════╣
║  CHANGES APPLIED                                             ║
║  ├─ Rules Created:  8                                        ║
║  ├─ Rules Modified: 3                                        ║
║  ├─ Rules Deleted:  1                                        ║
║  └─ Commit ID:      a3f7c2d1                                 ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 🏗️ Architecture

```
firewall-policy-automator/
├── firewall_automator.py    # Main automation script
├── config/
│   └── settings.yaml        # Connection settings
├── policies/
│   ├── templates/           # Jinja2 policy templates
│   └── production/          # Production policies
├── compliance/
│   ├── pci-dss.yaml        # PCI-DSS baseline
│   └── nist-800-53.yaml    # NIST baseline
├── reports/
│   └── audit_YYYYMMDD.html # Generated reports
└── requirements.txt
```

---

## 🔐 Security Best Practices

| Practice | Implementation |
|----------|----------------|
| API Key Storage | Use environment variables or vault |
| Least Privilege | Create dedicated API user with minimal permissions |
| Audit Logging | All operations logged with timestamps |
| Change Approval | Optional approval workflow integration |
| Backup | Automatic config backup before changes |

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [API Reference](docs/API.md) | Complete API documentation |
| [Configuration Guide](docs/CONFIG.md) | Setup and configuration |
| [Troubleshooting](docs/TROUBLESHOOT.md) | Common issues and solutions |
| [Contributing](CONTRIBUTING.md) | How to contribute |

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

### 👨‍💻 Author

**Tamer Khalifa** - *Network Automation Engineer*

[![CCIE](https://img.shields.io/badge/CCIE-68867-1BA0D7?style=flat-square&logo=cisco&logoColor=white)](https://www.cisco.com/c/en/us/training-events/training-certifications/certifications/expert.html)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat-square&logo=linkedin)](https://linkedin.com/in/tamerkhalifa2022)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat-square&logo=github)](https://github.com/tamersaid2022)

---

⭐ **Star this repo if you find it useful!** ⭐

</div>
