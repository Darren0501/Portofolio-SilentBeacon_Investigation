# Incident Response Portfolio

> Simulated attack detection and analysis in an isolated homelab environment.

## Overview

This repository documents a full **Incident Response (IR) analysis** of a simulated multi-stage attack called **SilentBeacon**, conducted in a controlled homelab environment running pfSense, Windows Active Directory, and Wazuh SIEM.

The goal is to demonstrate practical skills in:
- Threat detection via Wazuh/Sysmon telemetry
- Process tree forensic analysis
- MITRE ATT&CK technique mapping
- Incident timeline reconstruction
- SOC analyst documentation

## Environment
![Homelab Setup](Image/Homelab%20Configuration.png)

## Attack Summary
Using `Setup-Operation-Silent-Beacon-v2.ps1` in AttackScrip folder to simulate an attack.
SilentBeacon is a staged reconnaissance attack delivered via a masqueraded `.cmd` file. It executes a four-layer loader chain before performing comprehensive host discovery and staging collected data for exfiltration.

```
User Click → .cmd (masqueraded) → .ps1 → .cmd → .ps1 (orchestrator)
  → 11x Discovery Commands → Data Staging → Integrity Verification (certutil)
```

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|---|---|
| Initial Access | T1204.002 |
| Execution | T1059.001, T1059.003 |
| Defense Evasion | T1036.005, T1027 |
| Discovery | T1033, T1082, T1057, T1087.001, T1007, T1053.005, T1016, T1049 |
| Collection | T1074.001, T1560 |

## Report

📄 [Full Incident Response Report](./InvestigationResult/INCIDENT_REPORT.md)

## Investigation Processes

📄 [Investigation Processes](./InvestigationProcess/ANALYSIS_WALKTHROUGH.md)

## Skills Demonstrated

- Wazuh SIEM alert triage and investigation
- Sysmon process tree forensic reconstruction
- MITRE ATT&CK technique identification
- IOC extraction and documentation
- Detection gap analysis
- Incident response reporting

---

*All activities were performed in an isolated lab environment for educational and portfolio purposes.*
