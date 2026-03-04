# End-to-End SOC Lab: Attack Detection, Log Analysis & Incident Response (Splunk)

## Executive Summary

This project demonstrates the design and implementation of a **Security
Operations Center (SOC) lab** used to simulate real-world cyber attacks,
ingest telemetry, build detection rules, investigate incidents, and
implement automated defense using **Splunk SIEM**.

The lab integrates Windows endpoint telemetry, Linux authentication
logs, and simulated attacker activity to demonstrate detection
engineering and SOC investigation workflows aligned with the **MITRE
ATT&CK framework**.

Key achievements:

-   Built a complete telemetry pipeline using Splunk Universal Forwarder
-   Indexed **19,000+ security events**
-   Simulated multiple attack techniques
-   Developed detection rules using **Splunk SPL**
-   Created SOC alerts and dashboards
-   Conducted incident investigation workflows
-   Implemented automated containment using **Fail2Ban**
-   Developed **Sigma detection rules**
-   Performed threat hunting queries
-   Documented a SOC incident report

------------------------------------------------------------------------

# 1. Project Overview

This project replicates a small SOC environment where logs from Windows
and Linux systems are centralized into Splunk for analysis.

Objectives:

-   Understand SIEM architecture
-   Build a telemetry pipeline
-   Simulate attacker behavior
-   Create detection queries
-   Investigate security alerts
-   Map attacks to MITRE ATT&CK

Focus areas:

SIEM Engineering\
Log Ingestion\
Detection Engineering\
Threat Simulation\
Incident Investigation\
Automated Response

------------------------------------------------------------------------

# 2. Lab Architecture

The SOC lab consists of four virtual machines.

Windows 10 Endpoint\
Generates telemetry using Windows logs and Sysmon.

Ubuntu Splunk Server\
Acts as Splunk **Indexer + Search Head**.

Linux System Logs\
Provides SSH authentication telemetry.

Kali Linux\
Used to simulate attacker behavior.

## Architecture Diagram

![SOC Architecture](architecture/soc_lab_architecture.png)

## Data Flow

Kali Linux (Attacker) → Windows 10 Endpoint (Sysmon + Logs) → Splunk
Universal Forwarder → TCP Port 9997 → Splunk Indexer → SOC Analyst
Investigation

------------------------------------------------------------------------

# 3. Telemetry Sources

## Windows Security Logs

EventID 4624 --- Successful Logon\
EventID 4625 --- Failed Logon

## Sysmon Logs

EventID 1 --- Process Creation\
EventID 3 --- Network Connection\
EventID 11 --- File Creation

## Linux Logs

/var/log/auth.log --- SSH authentication logs

## Network Activity

Nmap scan activity\
Outbound network connections

------------------------------------------------------------------------

# 4. Tools & Environment

SIEM\
Splunk Enterprise (Ubuntu)

Endpoint Monitoring\
Microsoft Sysmon

Log Forwarding\
Splunk Universal Forwarder

Virtualization\
Oracle VM VirtualBox

Attack Simulation\
Kali Linux

Automated Defense\
Fail2Ban

------------------------------------------------------------------------

# 5. Repository Structure

architecture/\
detections/\
sigma-rules/\
threat-hunting/\
screenshots/\
reports/\
README.md

------------------------------------------------------------------------

# 6. Environment Setup

## Virtual Machines

Windows 10\
RAM: 4GB\
Disk: 60GB

Ubuntu Splunk Server\
RAM: 2GB\
Disk: 30GB

## Network Setup

Adapter 1 --- NAT (internet access)

Adapter 2 --- Host-Only network (internal attack lab)

------------------------------------------------------------------------

# 7. Log Collection Pipeline

Windows Logs Forwarded:

Security Logs\
System Logs\
Sysmon Operational Logs

Linux Logs Forwarded:

/var/log/auth.log\
/var/log/syslog

Splunk Index Used:

index=main

Screenshot

![Splunk Indexed Events](screenshots/splunk_index_events.png)

------------------------------------------------------------------------

# 8. Detection Strategy

The detection strategy focuses on identifying attacker behaviors mapped
to MITRE ATT&CK.

Primary attacker tactics monitored:

Credential Access\
Execution\
Discovery

Detection rules were validated using simulated attack activity.

------------------------------------------------------------------------

# 9. Attack Simulations

## Attack 1 --- SSH Brute Force

Attack Command

for i in {1..10}; do ssh attacker@localhost -p 22 "exit"; done

Log Source

Linux auth.log

Detection Query

index=main sourcetype="linux_secure" "Failed password" \| rex "Failed
password for (invalid user )?(?`<user>`{=html}`\w`{=tex}+) from
(?`<src_ip>`{=html}`\d+`{=tex}.`\d+`{=tex}.`\d+`{=tex}.`\d+`{=tex})" \|
bin \_time span=1m \| stats count by user src_ip \| where count \> 5

MITRE ATT&CK

Tactic: Credential Access\
Technique: Brute Force\
ID: T1110

Screenshot

![SSH Brute Force Detection](screenshots/ssh_bruteforce_detection.png)

------------------------------------------------------------------------

## Attack 2 --- Windows Credential Attack

Log Source

Windows Security Logs

Detection Query

index=main EventCode=4625 \| stats count by Account_Name
Source_Network_Address \| sort -count

MITRE ATT&CK

Tactic: Credential Access\
Technique: Brute Force\
ID: T1110

Screenshot

![Windows Failed Logins](screenshots/windows_failed_login.png)

------------------------------------------------------------------------

## Attack 3 --- Port Scan Detection

Attack Command

nmap -sS `<target-ip>`{=html}

Detection Query

index=main EventID=3 \| stats count by DestinationPort SourceIp \| sort
-count

MITRE ATT&CK

Tactic: Discovery\
Technique: Network Service Discovery\
ID: T1046

Screenshot

![Port Scan Detection](screenshots/port_scan_detection.png)

------------------------------------------------------------------------

## Attack 4 --- Encoded PowerShell Execution

Attack Command

powershell -EncodedCommand
UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAYQBsAGMALgBlAHgAZQA=

Detection Query

index=main EventID=1 "*EncodedCommand*"

MITRE ATT&CK

Tactic: Execution\
Technique: PowerShell\
ID: T1059.001

Screenshot

![Encoded PowerShell
Detection](screenshots/encoded_powershell_detection.png)

------------------------------------------------------------------------

## Attack 5 --- Suspicious Process Execution

Scenario

PowerShell spawning calc.exe

Detection Query

index=main EventID=1 Image="\*powershell.exe" \| table \_time host Image
CommandLine ParentImage

MITRE ATT&CK

Tactic: Execution\
Technique: Command Interpreter\
ID: T1059

Screenshot

![Suspicious Process Execution](screenshots/suspicious_process.png)

------------------------------------------------------------------------

# 10. Detection Engineering

Detection rules created:

SSH brute force detection\
Windows credential attack detection\
Encoded PowerShell detection\
Port scan detection\
Suspicious process execution detection

Each detection includes:

Detection logic\
SPL query\
MITRE mapping\
False positive considerations

------------------------------------------------------------------------

# 11. Sigma Detection Rules

Sigma is a platform‑agnostic detection rule format used to share
detection logic across SIEM platforms.

Example Sigma rule:

``` yaml
title: Suspicious Encoded PowerShell Execution
logsource:
  product: windows
  service: sysmon

detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc'

condition: selection
level: high
```

Stored in repository:

sigma-rules/encoded_powershell.yml

------------------------------------------------------------------------

# 12. Alert Engineering

Example Alert

Alert Name: SSH Brute Force Detection

Trigger Condition

More than 5 failed attempts in 1 minute.

Schedule

Every 1 minute

Severity

Medium

------------------------------------------------------------------------

# 13. Visualization

Splunk dashboards visualize attack patterns.

Examples:

Brute force attack timeline\
Top targeted users\
Top source IP addresses

Screenshot

![Splunk Dashboard](screenshots/splunk_dashboard.png)

------------------------------------------------------------------------

# 14. Threat Hunting Queries

Example Hunting Query --- Most Frequent Processes

index=main EventID=1 \| stats count by Image \| sort -count

Example --- Suspicious PowerShell Activity

index=main Image="\*powershell.exe" \| stats count by CommandLine

Threat hunting queries stored in:

threat-hunting/

------------------------------------------------------------------------

# 15. MITRE ATT&CK Mapping

  -----------------------------------------------------------------------
  Attack            Tactic            Technique         ID
  ----------------- ----------------- ----------------- -----------------
  SSH Brute Force   Credential Access Brute Force       T1110

  Windows Logon     Credential Access Brute Force       T1110
  Failure                                               

  Encoded           Execution         PowerShell        T1059.001
  PowerShell                                            
  Execution                                             

  Port Scan         Discovery         Network Service   T1046
                                      Discovery         

  Suspicious        Execution         Command           T1059
  Process Execution                   Interpreter       
  -----------------------------------------------------------------------

------------------------------------------------------------------------

# 16. SOC Investigation Workflow

Example workflow

Alert triggered → SOC analyst reviews logs → Process tree analysis →
Timeline reconstruction → MITRE ATT&CK mapping → Incident documentation

Example Process Tree

cmd.exe\
→ powershell.exe\
→ calc.exe

Screenshot

![Process Tree Analysis](screenshots/process_tree_analysis.png)

------------------------------------------------------------------------

# 17. SOC Incident Report

Incident Name

Encoded PowerShell Execution

Host

Windows Endpoint

Detection

index=main EventID=1 "*EncodedCommand*"

Process Chain

cmd.exe\
→ powershell.exe\
→ calc.exe

MITRE ATT&CK

T1059.001

Conclusion

Suspicious PowerShell command execution detected and investigated.

Full report located in

reports/powershell_incident_report.md

------------------------------------------------------------------------

# 18. Automated Defense --- Fail2Ban

Fail2Ban monitors authentication logs and blocks brute‑force attackers.

Configuration

/etc/fail2ban/jail.local

Settings

maxretry = 3\
bantime = 1h

Screenshot

![Fail2Ban Status](screenshots/fail2ban_status.png)

------------------------------------------------------------------------

# 19. Troubleshooting

Issue 1

Logs not appearing in Splunk.

Root Cause

inputs.conf had a hidden .txt extension.

Resolution

Corrected configuration and restarted forwarder.

Result



Issue 2

Logs not appearing in Splunk.

Root Cause

Permissions issue , Gave permissions in LOG On Tab of the service Splunkforwarder and restarted the service.

Resolution

Gave permissions in LOG On Tab of the service Splunkforwarder and restarted the service.

Result
Logs started appearing in the Splunk after searching a query

38,000+ events successfully indexed.



------------------------------------------------------------------------

# 20. SOC Metrics

Events indexed: 19,000+\
Data sources: 4\
Detection rules created: 5\
Attack simulations executed: 5\
Alert response time: \<1 minute

------------------------------------------------------------------------

# 21. Lessons Learned

Importance of Sysmon configuration\
Challenges with SIEM log ingestion\
Detection tuning to reduce false positives\
Correlation of logs across multiple systems

------------------------------------------------------------------------

# 22. Skills Demonstrated

SIEM Engineering\
Log Pipeline Troubleshooting\
Detection Engineering\
Threat Simulation\
Security Log Analysis\
SOC Investigation Workflow\
Endpoint Telemetry Analysis
