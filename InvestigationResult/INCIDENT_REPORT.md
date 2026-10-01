# 🔍 Incident Response Report
## SilentBeacon — Staged Reconnaissance & Pre-Exfiltration Attack

---

```
Date            : September 30, 2026
Analyst         : Darren Gavriel Suntara
Environment     : ECorp Homelab Simulation
Status          : Contained
```

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Incident Timeline](#2-incident-timeline)
3. [Process Tree](#3-process-tree)
4. [Attack Analysis](#4-attack-analysis)
5. [Evidence Table](#5-evidence-table)
6. [MITRE ATT&CK Mapping](#6-mitre-attck-mapping)
7. [Root Cause Analysis](#7-root-cause-analysis)
8. [Impact Assessment](#8-impact-assessment)
9. [Containment & Remediation](#9-containment--remediation)
10. [Lessons Learned](#10-lessons-learned)

---

## 1. Executive Summary

On **September 30, 2026**, a multi-stage attack was detected on workstation **DESKTOP-S9N6621** (IP: `10.0.1.2`) within the ECorp domain environment. The attack, designated **SilentBeacon**, was executed through a masqueraded Windows command script disguised as a legitimate Microsoft Office compatibility update.

The attacker established a **four-stage execution chain** (`.cmd → .ps1 → .cmd → .ps1`) designed to appear benign at each individual layer. The final stage performed **comprehensive host reconnaissance**, collecting 11 distinct system artifacts and staging them to a hidden directory on the target host. The attack concluded with an **integrity verification step using `certutil`**, strongly indicating the staged data was prepared for exfiltration.

**No exfiltration was confirmed** during the observed window, however all prerequisite staging activity had been completed at the time of detection.

| | |
|---|---|
| **Initial Vector** | User (pprice) execution of masqueraded `.cmd` file |
| **Techniques Used** | Masquerading, Multi-stage Loader, Discovery, Data Staging |
| **Systems Affected** | DESKTOP-S9N6621 (wrk-price, 10.0.1.2) |
| **Data at Risk** | System config, user accounts, network topology, process list, scheduled tasks |

---


## 3. Incident Timeline

> Timestamps are derived from Wazuh/Sysmon event logs. Fill in actual timestamps from your Wazuh dashboard.

| Timestamp (UTC) | Event |
|---|---|
| `[T+00:00]` | `Office_Compatibility_Update.cmd` spawned by `explorer.exe` — user execution | 
| `[T+00:01]` | `CompatibilityCheck.ps1` launched and Stage 1 loader; `session_context.txt` written | 
| `[T+00:01]` | `TelemetryCache.cmd` launched and Stage 2 loader; `stage2_marker.txt` written | 
| `[T+00:02]` | `SystemHealth.ps1` launched and Main orchestrator begins execution | 
| `[T+00:02]` | Batch discovery commands begin: `whoami`, `hostname`, `systeminfo` | 
| `[T+00:03]` | Network discovery: `ipconfig`, `route print`, `arp -a`, `netstat -ano` | 
| `[T+00:03]` | Account discovery: `net user`, `sc.exe query`, `schtasks.exe /query` | 
| `[T+00:04]` | DNS resolution test: `nslookup example.com` | 
| `[T+00:04]` | Loopback connectivity test: `PING.exe -n 3 127.0.0.1` | 
| `[T+00:04]` | Registry query for OS version: `req.exe HKLM\...\ProductName` | 
| `[T+00:05]` | `PackageReports.ps1` launched, finalization stage | 
| `[T+00:05]` | `FinalizeUpdate.cmd` spawned and writes completion markers | 
| `[T+00:06]` | `certutil.exe -hashfile ... SHA256` , integrity verification of staged data | 
| `[T+00:06]` | `Quarterly_Workstation_Review.txt` hash computed, **pre-exfiltration confirmed** | 

---

## 4. Process Tree

![Process Tree](/InvestigationResult/Image/SlilentBeacon_ProcessTree.png)

---

## 5. Attack Analysis

### 5.1 Stage 1 — Initial Execution (Masquerading)

The attack chain was initiated when a user (pprice) executed `Office_Compatibility_Update.cmd` from **File Explorer** (`explorer.exe`). The filename is deliberately crafted to impersonate a legitimate Microsoft Office update mechanism — a classic **social engineering** lure.

**Parent-child relationship:**
```
explorer.exe
  └── Office_Compatibility_Update.cmd
```

> **Analyst Note:** The spawn of a `.cmd` file directly from `explorer.exe` is a high-confidence indicator of **user-initiated execution**, not a system or service process. This implies the user was deceived into running the file, likely via a phishing email, malicious download, or removable media.

---

### 5.2 Stage 2 — Multi-Layer Loader Chain

Rather than executing the malicious payload directly, the attacker implemented a **four-layer staging chain**:

```
Office_Compatibility_Update.cmd   → "entry point"
  └── CompatibilityCheck.ps1      → stage 1 PS loader
        └── TelemetryCache.cmd    → stage 2 CMD relay
              └── SystemHealth.ps1 → main orchestrator
```

Each layer uses benign-sounding names mimicking legitimate Windows/Office telemetry processes. This design serves two purposes:
1. **Evade static detection** — no single file appears overtly malicious
2. **Complicate forensic attribution** — analyst must traverse multiple layers to identify the true payload

Each loader writes a marker file (`session_context.txt`, `stage2_marker.txt`) to a working directory — likely used for **execution flow control** (ensuring previous stages completed before proceeding).

---

### 5.3 Stage 3 — Comprehensive Discovery

`SystemHealth.ps1` acts as the main orchestrator, spawning a `cmd.exe` child process that executes 11 sequential discovery commands, each redirecting output to individual files under `C:\Public\Downloads\SilentBeacon\working\`:

| Command | Output File | Category |
|---|---|---|
| `whoami /all` | `identity.txt` | User & Privilege Context |
| `hostname` | `hostname.txt` | System Identification |
| `systeminfo` | `system_profile.txt` | System Enumeration |
| `tasklist` | `running_process.txt` | Process Discovery |
| `net user` | `local_account.txt` | Account Discovery |
| `sc.exe query state=all` | `services.txt` | Service Discovery |
| `schtasks.exe /query state=all` | `scheduled_task.txt` | Scheduled Task Discovery |
| `ipconfig /all` | `network_config.txt` | Network Configuration |
| `route print` | `routes.txt` | Network Routing |
| `arp -a` | `arp_cache.txt` | ARP / Local Network Map |
| `netstat -ano` | `network_connections.txt` | Active Connections |

In parallel, `SystemHealth.ps1` spawns three additional probes:
- `nslookup example.com` — confirms **outbound DNS resolution** is available (network egress check)
- `PING.exe -n 3 127.0.0.1` — loopback connectivity baseline
- `req.exe HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion /v ProductName` — OS version via registry (more covert than `systeminfo`)

> **Analyst Note:** The DNS resolution check against `example.com` (an external domain) is particularly significant. Attackers typically perform this test to confirm the host can reach the internet before attempting exfiltration. A successful `nslookup` here implies **exfiltration was planned** and the network path was verified.

---

### 5.4 Stage 4 — Data Staging & Integrity Verification

The final execution stage is handled by `PackageReports.ps1`, which launches `FinalizeUpdate.cmd`. This writes three completion markers:
- `finalization_started.txt`
- `System_Update_Status.csv`
- `completed.txt`

The most critical artifact in this stage is:
```
certutil.exe -hashfile C:\Public\Downloads\SilentBeacon\working\Quarterly_Workstation_Review.txt SHA256
```

**`certutil.exe`** is a native Windows binary commonly abused by attackers (LOLBin). In this context, it is computing a **SHA256 hash of the staged data file**, a standard pre-exfiltration integrity check to ensure data was not corrupted before transmission.

> **Analyst Note:** The use of `certutil` for hash verification, combined with the DNS egress check in the previous stage, constitutes a strong behavioral indicator of **imminent data exfiltration** that was interrupted or deferred beyond the observed window.

---

## 6. Evidence Table

| # | Artifact | Type | Location | Significance | MITRE |
|---|---|---|---|---|---|
| E-01 | `Office_Compatibility_Update.cmd` | Malicious File | `C:\Public\Downloads\SilentBeacon\` | Initial execution entry point, masqueraded as Office update | T1036.005 |
| E-02 | `CompatibilityCheck.ps1` | Loader Script | `C:\Public\Downloads\SilentBeacon\cache\` | Stage 1 PowerShell loader | T1059.001 |
| E-03 | `TelemetryCache.cmd` | Loader Script | `C:\Public\Downloads\SilentBeacon\cache\` | Stage 2 CMD relay | T1059.003 |
| E-04 | `SystemHealth.ps1` | Orchestrator | `C:\Public\Downloads\SilentBeacon\cache\` | Main discovery orchestrator | T1059.001 |
| E-05 | `session_context.txt` | Marker File | `C:\Public\Downloads\SilentBeacon\reports\` | Stage execution flow marker | T1074.001 |
| E-06 | `stage2_marker.txt` | Marker File | `C:\Public\Downloads\SilentBeacon\reports\` | Stage execution flow marker | T1074.001 |
| E-07 | `identity.txt` | Collected Data | `C:\Public\Downloads\SilentBeacon\working\` | Victim user identity & privileges | T1033 |
| E-08 | `system_profile.txt` | Collected Data | `C:\Public\Downloads\SilentBeacon\working\` | Full system information | T1082 |
| E-09 | `running_process.txt` | Collected Data | `C:\Public\Downloads\SilentBeacon\working\` | Active process list | T1057 |
| E-10 | `local_account.txt` | Collected Data | `C:\Public\Downloads\SilentBeacon\working\` | Local user accounts | T1087.001 |
| E-11 | `services.txt` | Collected Data | `C:\Public\Downloads\SilentBeacon\working\` | Running Windows services | T1007 |
| E-12 | `scheduled_task.txt` | Collected Data | `C:\Public\Downloads\SilentBeacon\working\` | Scheduled tasks inventory | T1053.005 |
| E-13 | `network_config.txt` | Collected Data | `C:\Public\Downloads\SilentBeacon\working\` | Full network interface configuration | T1016 |
| E-14 | `network_connections.txt` | Collected Data | `C:\Public\Downloads\SilentBeacon\working\` | Active TCP/UDP connections with PIDs | T1049 |
| E-15 | `arp_cache.txt` | Collected Data | `C:\Public\Downloads\SilentBeacon\working\` | ARP cache — reveals other hosts on segment | T1016 |
| E-16 | `routes.txt` | Collected Data | `C:\Public\Downloads\SilentBeacon\working\` | Routing table — network path info | T1016 |
| E-17 | `PackageReports.ps1` | Staging Script | `C:\Public\Downloads\SilentBeacon\` | Data finalization & packaging | T1560 |
| E-18 | `certutil.exe` execution | LOLBin Abuse | System32 | SHA256 hash of staged file — pre-exfiltration integrity check | T1560, T1027 |
| E-19 | `nslookup example.com` | Network Probe | N/A | External DNS egress confirmation | T1016.001 |
| E-20 | `Quarterly_Workstation_Review.txt` | Staged Package | `C:\Public\Downloads\SilentBeacon\working\` | Compiled data package ready for exfiltration | T1074.001 |

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| **Initial Access** | Phishing / User Execution | T1204.002 | `explorer.exe` → `.cmd` execution |
| **Execution** | Windows Command Shell | T1059.003 | `Office_Compatibility_Update.cmd`, `TelemetryCache.cmd`, `FinalizeUpdate.cmd` |
| **Execution** | PowerShell | T1059.001 | `CompatibilityCheck.ps1`, `SystemHealth.ps1`, `PackageReports.ps1` |
| **Defense Evasion** | Masquerading: Match Legitimate Name | T1036.005 | All scripts named to mimic Windows/Office processes |
| **Defense Evasion** | LOLBin: certutil | T1027 | `certutil.exe -hashfile` |
| **Discovery** | System Owner/User Discovery | T1033 | `whoami /all` |
| **Discovery** | System Information Discovery | T1082 | `systeminfo`, `hostname`, `req.exe` registry query |
| **Discovery** | Process Discovery | T1057 | `tasklist` |
| **Discovery** | Account Discovery: Local Account | T1087.001 | `net user` |
| **Discovery** | System Service Discovery | T1007 | `sc.exe query state=all` |
| **Discovery** | Scheduled Task Discovery | T1053.005 | `schtasks.exe /query state=all` |
| **Discovery** | System Network Configuration | T1016 | `ipconfig /all`, `route print`, `arp -a` |
| **Discovery** | Network Connection Discovery | T1049 | `netstat -ano` |
| **Discovery** | DNS/Network Egress Check | T1016.001 | `nslookup example.com` |
| **Collection** | Data Staged: Local Data Staging | T1074.001 | All output redirected to `SilentBeacon\working\` |
| **Collection** | Archive / Package | T1560 | `Quarterly_Workstation_Review.txt` compiled, SHA256 verified |

---

## 7. Root Cause Analysis

### Primary Root Cause
**Successful user execution of a masqueraded malicious script.**

The attack did not exploit any software vulnerability. It succeeded entirely through **social engineering** — a user (pprice) on `DESKTOP-S9N6621` was deceived into executing `Office_Compatibility_Update.cmd`, which was designed to appear as a legitimate Microsoft Office maintenance task.

### Contributing Factors

| Factor | Description |
|---|---|
| **No application allowlisting** | The endpoint permitted execution of arbitrary `.cmd` and `.ps1` files from user-writable directories without restriction |
| **PowerShell Script Block Logging gap** | Real-time alerting on PowerShell execution chains was not tuned to catch multi-stage loaders early |
| **Permissive write access** | The attacker was able to stage files to `C:\Public\Downloads\`, a world-writable directory. Restrictive ACLs would have impeded or broken the staging chain |

---

## 8. Impact Assessment

| Category | Impact | Detail |
|---|---|---|
| **Confidentiality** | HIGH | System profile, user accounts, network topology, running processes, and active connections were collected |
| **Integrity** | LOW | No system modifications confirmed beyond file creation in `SilentBeacon\` directory |
| **Availability** | NONE | No service disruption observed |
| **Lateral Movement Risk** | MEDIUM | ARP cache and network connection data expose other hosts in the segment — enables attacker to map further targets |
| **Exfiltration Risk** | HIGH | Data staged and integrity-verified — exfiltration is the clear next step |
| **Credential Risk** | MEDIUM | `net user` output exposes local account names; full credential dump was not observed in this stage |

---

## 9. Containment & Remediation

### Immediate Actions (0–2 hours)
- [ ] **Isolate** DESKTOP-S9N6621 from the network (disable NIC or quarantine via pfSense rule)
- [ ] **Preserve evidence** - do not reboot or run antivirus yet; take a full disk image first
- [ ] **Collect** the entire `C:\Public\Downloads\SilentBeacon\` directory as forensic evidence
- [ ] **Check network logs** for any outbound connections from 10.0.1.2 post-`certutil` execution, confirm if exfiltration occurred
- [ ] **Identify delivery vector** - check browser download history, email client (Outlook/Thunderbird), recent USB mounts, and `%TEMP%` for the origin of `Office_Compatibility_Update.cmd`

### Short-Term Remediation (1–7 days)
- [ ] **Implement PowerShell Constrained Language Mode** or **Execution Policy** to restrict arbitrary PS1 execution from user-writable paths
- [ ] **Add Wazuh rules** for:
  - LOLBin abuse (`certutil -hashfile`, `certutil -decode`)
  - Bulk sequential child process spawning from PowerShell
  - File creation bursts in `C:\Public\` or `%USERPROFILE%\Downloads\`
- [ ] **Restrict write permissions** on `C:\Public\` — remove world-writable access
- [ ] **Add DNS filtering** (pfSense with pfBlockerNG or external DNS sinkhole) to alert/block unexpected external DNS from workstations

### Long-Term Hardening (1–4 weeks)
- [ ] **Deploy application allowlisting** (Windows Defender Application Control / AppLocker) to prevent execution of unauthorized scripts
- [ ] **Implement network egress filtering** - workstations should not have unrestricted outbound internet access
- [ ] **User awareness training** - focus on script/document execution from untrusted sources
- [ ] **Implement file integrity monitoring** on sensitive directories

---

## 10. Lessons Learned

### What Went Well
- Sysmon telemetry (Event ID 1, 11) captured sufficient detail to **reconstruct the full attack chain post-facto**
- Wazuh successfully collected and indexed events from the affected host throughout the attack
- The process tree could be fully reconstructed from `parentImage`/`image` relationships in Sysmon logs

### What Needs Improvement
- **Correlation was manual** - no automated rule connected the four execution stages as a single attack chain; an analyst had to manually trace the process tree

### Key Takeaway

> *"SilentBeacon demonstrates that an attacker does not need exploits or elevated privileges to conduct meaningful pre-exfiltration reconnaissance. A single user click, combined with a multi-stage loader chain of legitimately-named scripts, was sufficient to enumerate the full host environment and stage data for exfiltration — all while generating only fragmented, individually low-severity log entries that required manual correlation to interpret as an attack."*

---


## References

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Sysmon Configuration](https://github.com/SwiftOnSecurity/sysmon-config)
- [Wazuh Documentation](https://documentation.wazuh.com)
- [LOLBins Reference — certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)

---

*Report generated as part of cybersecurity portfolio — ECorp Homelab Simulation*
*All activities conducted in an isolated lab environment*
