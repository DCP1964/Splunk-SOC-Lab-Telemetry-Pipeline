# Detection Engineering Rules

This folder contains Splunk detection rules developed during the SOC lab project.  
Each detection identifies suspicious behavior observed during simulated attack scenarios.

The detections are based on telemetry collected from:

- Windows Security Logs
- Sysmon Process Creation Logs
- Sysmon Network Connection Logs
- Linux SSH Authentication Logs

All detections are mapped to the **MITRE ATT&CK framework**.

---

# Detection Rules Overview

| Detection Name | Description | Log Source | MITRE Technique |
|----------------|-------------|------------|----------------|
SSH Brute Force | Detects repeated SSH login failures from the same IP | Linux auth.log | T1110 |
Windows Logon Failure | Detects repeated failed Windows login attempts | Windows Security Logs | T1110 |
Encoded PowerShell Execution | Detects Base64 encoded PowerShell commands | Sysmon Process Creation | T1059.001 |
Port Scan Detection | Detects abnormal network scanning behavior | Sysmon Network Events | T1046 |
Suspicious Process Execution | Detects suspicious PowerShell execution chains | Sysmon Process Creation | T1059 |

---

# Detection Strategy

The detection strategy focuses on identifying attacker techniques commonly used during the early stages of a cyber attack:

Credential Access  
Execution  
Discovery  

The detections were validated using simulated attack scenarios executed in the SOC lab environment.

---

# Example Detection Query

Example detection used to identify encoded PowerShell execution:
