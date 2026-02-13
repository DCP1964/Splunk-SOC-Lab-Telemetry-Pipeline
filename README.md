# Splunk-SOC-Lab-Telemetry-Pipeline
An end-to-end SOC lab featuring a Windows 10 endpoint, Sysmon telemetry, and an Ubuntu-based Splunk SIEM for threat detection.

# End-to-End SOC Lab: Splunk Telemetry Pipeline

## Overview
Successfully built a functional Security Operations Center (SOC) lab to monitor Windows endpoint activity using Splunk SIEM. This project demonstrates my ability to configure telemetry agents, manage log ingestion, and troubleshoot complex data pipeline issues.

## Project Goals 
- **Build a SOC lab from scratch** 
- **Collect logs** 
- **Detect attacks** 
- **Investigate incidents**
- **Write detection reports**
- **Use Splunk like a real analyst**

## Tools & Environment
- **SIEM:** Splunk Enterprise (Ubuntu Server 24.04)
- **Endpoint:** Windows 10 Pro
- **Telemetry:** Microsoft Sysmon & Splunk Universal Forwarder
- **Virtualization:** Oracle VM VirtualBox

## Architecture
1. **Windows 10 Victim:** Generates Event Logs and Sysmon telemetry.
2. **Splunk Universal Forwarder:** Sends data over port 9997.
3. **Ubuntu Splunk Server:** Ingests, indexes, and visualizes the data.
4. **Sysmon** ( for deep logging)
5. **Kali Linux**
6. **VirtualBox**

## Demonstrating
- **Brute force detection**
- **Malware simulation**
- **Port scanning detection**
- **Suspicious PowerShell detection**
- **Log correlation**
- **Incident report writing**

## Creating Machines
- **VM 1 — Windows 10**
    - **RAM:** 4GB
    - **Disk:** 60GB
- **VM 2 — Ubuntu Server**
    - **RAM:** 2GB
    - **Disk:** 30GB
- **VM 3 — Splunk Server**
    - **OS Ubuntu Server**

## Network Setup 
- **Adapter 1 = NAT**
- **Adapter 2 = Host-Only**
    - This allows
      - **Inernet Access**
      - **Internal attack lab**

## INSTALL SPLUNK ENTERPRISE (SIEM)

**On Ubuntu Splunk VM:**

**Go to:**
[https://www.splunk.com](https://www.splunk.com)

**Download:**
- Splunk Enterprise (Linux .deb)   

**Install:**

`sudo dpkg -i splunk*.deb sudo /opt/splunk/bin/splunk start`

**Create:**
- Username-- admin    
- Password: password123
    

**Open in browser:**

`http://localhost:8000`

## INSTALL SPLUNK FORWARDER (Windows)

**On Windows VM:**
**Download:**
- **Splunk Universal Forwarder*

**Install and choose:**

`Forward to: <IP_of_Splunk_Server>:9997`

## INSTALL SYSMON 
**Sysmon gives deep visibility like an EDR.**
    - **On Windows VM:**
    - **Download Sysmon from Microsoft**
    
**Then install:**

`Sysmon64.exe -i sysmonconfig.xml`

**Use config:**
- **SwiftOnSecurity sysmon config (Google it)**
This logs:
- **Process creation**    
- **Malware behavior**    
- **Network connections**    
- **PowerShell attacks**

## CONNECT WINDOWS LOGS TO SPLUNK

**Forward:**-
    - **Security Logs**    
    - **System Logs**    
    - **Sysmon Logs**  

**To Splunk**

## INSTALL LOGGING ON UBUNTU
**On Ubuntu machine:**
**Install auditd:**

`sudo apt install auditd`

**Install Splunk Forwarder**
**Forward:**

`/var/log/auth.log` 
`/var/log/syslog`

## ATTACK SIMULATION
**Simulate real attacks:**

# Attack 1:

**Port scan:**

`nmap -sS <Windows_IP>`

# Attack 2:

**Brute force:**

`hydra -l admin -P rockyou.txt <IP> ssh`

# Attack 3:

Fake malware:

Create suspicious PowerShell execution.

# Attack 4 (On your Ubuntu Server) :
**Open the terminal on your Ubuntu VM**
- **Run this command to try and log in as a fake user named "attacker" 10 times:**


`for i in {1..10}; do ssh attacker@localhost -p 22 "exit"; done`
-- **When it asks for a password, just hit Enter or type random letters and press Enter.**
-- **After 10 tries, your Ubuntu system will record 10 "Failed password" events in the auth logs.**

## The Verification (Is Splunk Watching?)
**Open Splunk Web UI (http://10.0.0.109:8000) and run this search to see if the "attacker" was caught:**

`index="internal" "failed password" | stats count by user, src_ip`

**Expected Result: You should see the user attacker with a count of 10**

## The "Next Level" Goal: Automated Alerting
**In a real SOC, we can't stare at the screen 24/7. We want Splunk to tell us when something is wrong.**

# How to Create your first SOC Alert:
**Run a search that finds the brute force:**

`index="internal" "failed password" | stats count by user | where count > 5`

**Click Save As in the top right.**
    - **Select Alert.**
    - **Title: Brute Force Attempt Detected**
    - **Trigger Conditions: Set to "Greater than 5" within a "1 minute" window.**
    - **Action: For now, set it to "Add to Triggered Alerts".**



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
