# CIS-macOS-15.0-Sequoia-Compliance-Audit

This Bash script audits all **107 CIS (Center for Internet Security) benchmarks** for macOS 15.0 Sequoia (Level 1 & 2 profiles), focusing on MDM (Mobile Device Management) configurations via Intune or similar, alongside system settings. It checks controls across sections like Software Updates, Accounts, Restrictions, Security, Logging, Network, System Access, and Applications.

## Features
- **Automated Auditing**: Scans MDM profiles (`profiles show`) and system prefs (`defaults read`, `pwpolicy`, etc.).
- **Compliance Reporting**: Generates JSON, HTML (with pie chart via Chart.js), and CSV reports.
- **Progress Tracking**: Real-time console progress bar and verbose logging.
- **Remediation Guidance**: Provides Proof-of-Concept (PoC) steps for non-compliant controls, tailored for Microsoft Intune.
- **Sections Covered**:
  - Section 1: Software Updates (6 controls)
  - Section 2: Accounts & Policies (84 controls)
  - Section 3: Logging & Auditing (5 controls)
  - Section 4: Network Configurations (5 controls)
  - Section 5: System Access (15 controls)
  - Section 6: Applications (7 controls)

## Requirements
- **OS**: macOS 15.0 Sequoia (tested on Apple Silicon).
- **Permissions**: Run as root (`sudo`).
- **Tools**: Built-in macOS commands (`profiles`, `defaults`, `pwpolicy`, `plutil`, etc.). No external dependencies.
- **MDM**: Optional but recommended (e.g., Intune) for full coverage; falls back to local checks.

## Usage
1. **Download & Make Executable**:
   
chmod +x CIS_MACOS_15_0_MDM_Compliance.sh

2. **Run the Audit**:

sudo ./CIS_MACOS_15_0_MDM_Compliance.sh         # Standard mode
sudo ./CIS_MACOS_15_0_MDM_Compliance.sh -v      # Verbose mode

3. **Output Files** (generated in `/tmp` and `/var/log`):
- `/tmp/compliance.json`: Machine-readable JSON summary.
- `/tmp/compliance_report.html`: Interactive HTML report with charts and tooltips (open in browser).
- `/tmp/compliance_report.csv`: Spreadsheet-friendly export.
- `/var/log/cis_macos_15_0_compliance.log`: Detailed logs.
