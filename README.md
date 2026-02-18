# End-to-End SOC Lab: Splunk Telemetry Pipeline

## Executive Summary

This project demonstrates the design and implementation of a fully
functional Security Operations Center (SOC) telemetry pipeline. The lab
simulates real-world attack scenarios against a Windows 10 endpoint and
Linux server, collects telemetry using Sysmon and native logging,
forwards events to Splunk Enterprise SIEM, and implements detection,
alerting, investigation, and automated response mechanisms.

This project highlights practical SOC engineering skills including log
pipeline troubleshooting, detection rule creation, MITRE ATT&CK mapping,
incident investigation, and defensive hardening.

------------------------------------------------------------------------

## Objectives

-   Build a multi-machine SOC lab from scratch
-   Collect and forward Windows and Linux logs to Splunk
-   Simulate real-world attacks
-   Create detection rules using SPL
-   Investigate security incidents
-   Implement automated defensive controls

------------------------------------------------------------------------

## Lab Architecture

### Components

-   Windows 10 Endpoint (Sysmon + Windows Event Logs)
-   Ubuntu Server (Splunk Enterprise SIEM)
-   Kali Linux (Attack Simulation)
-   Splunk Universal Forwarder
-   Fail2Ban (Automated Response)

### Data Flow

Windows & Linux Logs → Splunk Universal Forwarder → Splunk Indexer (Port
9997) → Detection & Alerting

------------------------------------------------------------------------

## Tools & Technologies

-   Splunk Enterprise (Ubuntu Server 24.04)
-   Splunk Universal Forwarder
-   Microsoft Sysmon (SwiftOnSecurity configuration)
-   Kali Linux (Attack Simulation)
-   Oracle VM VirtualBox
-   Fail2Ban
-   auditd (Linux logging)

------------------------------------------------------------------------

## Attack Simulations & MITRE ATT&CK Mapping

  ------------------------------------------------------------------------------
  Attack Simulation         Description       MITRE Technique        ID
  ------------------------- ----------------- ---------------------- -----------
  SSH Brute Force           Multiple failed   Credential Access      T1110
                            login attempts                           

  PowerShell Execution      Suspicious script Command & Scripting    T1059.001
                            execution         Interpreter            

  Port Scanning             Nmap SYN scan     Network Service        T1046
                                              Discovery              

  Malware Simulation        Suspicious        Execution              T1204
                            process creation                         
  ------------------------------------------------------------------------------

------------------------------------------------------------------------

## Detection Engineering

### 1️⃣ SSH Brute Force Detection

SPL Query:

    index="main" sourcetype="linux_secure" "Failed password"
    | stats count by user, src_ip
    | where count > 5

Detection Logic: Identifies more than five failed login attempts from a
single source, indicating potential credential brute force.

False Positives Considered: - User mistyped password - Misconfigured
automation scripts

------------------------------------------------------------------------

### 2️⃣ Suspicious PowerShell Execution

SPL Query:

    index="main" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe*"

Detection Logic: Monitors Sysmon Event ID 1 (Process Creation) for
PowerShell execution, often used in malicious scripting.

------------------------------------------------------------------------

## Incident Investigation Walkthrough

1.  Alert triggered due to threshold breach.
2.  Pivoted using src_ip and user fields.
3.  Correlated events across time using timechart.
4.  Confirmed repeated authentication failures.
5.  Validated malicious behavior pattern.
6.  Escalated and applied containment via Fail2Ban.

------------------------------------------------------------------------

## Automated Response (Fail2Ban)

Policy: - 3 failed attempts - 1-hour ban

Outcome: Successfully blocked simulated attacker IP after threshold
violation.

------------------------------------------------------------------------

## SOC Metrics

-   Total Events Indexed: 19,000+
-   Data Sources: Windows Security, System, Sysmon, Linux auth.log
-   Detection Rules Created: 4
-   Alerts Configured: 3
-   Attack Scenarios Simulated: 4

------------------------------------------------------------------------

## Troubleshooting & Engineering Challenges

### Data Silent Issue

-   Verified network connectivity (Port 9997 ESTABLISHED)
-   Reviewed splunkd.log for ingestion errors
-   Identified hidden .txt extension in inputs.conf
-   Cleared fishbucket to force re-indexing

Resolution demonstrated advanced understanding of Splunk ingestion
pipeline.

------------------------------------------------------------------------

## Lessons Learned

-   Importance of properly tuning Sysmon configurations
-   Detection thresholds must balance false positives
-   Log pipeline validation is critical in SOC environments
-   Automated response reduces analyst fatigue

------------------------------------------------------------------------

## Professional Skills Demonstrated

-   SIEM Engineering
-   Log Pipeline Troubleshooting
-   Detection Rule Development (SPL)
-   MITRE ATT&CK Mapping
-   Incident Investigation
-   Defensive Hardening & Automation

------------------------------------------------------------------------

## Conclusion

This SOC lab replicates real-world blue team workflows including
telemetry ingestion, detection engineering, investigation, and automated
mitigation. The project reflects practical experience aligned with SOC
Analyst and Detection Engineer roles.
