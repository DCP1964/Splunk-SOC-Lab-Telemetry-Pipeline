# Splunk-SOC-Lab-Telemetry-Pipeline
An end-to-end SOC lab featuring a Windows 10 endpoint, Sysmon telemetry, and an Ubuntu-based Splunk SIEM for threat detection.

# End-to-End SOC Lab: Splunk Telemetry Pipeline

## Overview
Successfully built a functional Security Operations Center (SOC) lab to monitor Windows endpoint activity using Splunk SIEM. This project demonstrates my ability to configure telemetry agents, manage log ingestion, and troubleshoot complex data pipeline issues.

## Tools & Environment
- **SIEM:** Splunk Enterprise (Ubuntu Server 24.04)
- **Endpoint:** Windows 10 Pro
- **Telemetry:** Microsoft Sysmon & Splunk Universal Forwarder
- **Virtualization:** Oracle VM VirtualBox

## Architecture
1. **Windows 10 Victim:** Generates Event Logs and Sysmon telemetry.
2. **Universal Forwarder:** Sends data over port 9997.
3. **Ubuntu Splunk Server:** Ingests, indexes, and visualizes the data.

## The "SOC Mindset": Troubleshooting Log Ingestion
During the setup, I encountered a "Data Silent" issue where the connection was established but logs were not indexing. I resolved this through:
- **Network Analysis:** Verified the `ESTABLISHED` state on the Ubuntu server using `netstat`.
- **Log Forensics:** Analyzed `splunkd.log` on the Windows endpoint to find connection errors.
- **Root Cause:** Identified a hidden `.txt` extension on `inputs.conf` and a service permission mismatch.
- **Solution:** Renamed the config, elevated the service to `Local System`, and cleared the `fishbucket` to force re-ingestion.

## Result: 19,000+ Events Successfully Indexed
![Splunk Data Evidence](img/final_search.png)
Successfully captured:
- **WinEventLog:Security** (Logon/Logoff events)
- **WinEventLog:System** (Service changes)
- **Sysmon:Operational** (Process creation, Network connections)
