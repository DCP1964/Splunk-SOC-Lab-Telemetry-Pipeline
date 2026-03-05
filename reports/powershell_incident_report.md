# SOC Incident Reports

This folder contains incident investigation reports generated during the SOC lab project.

Each report documents a security alert detected by Splunk SIEM and investigated using SOC analyst workflows.

The purpose of these reports is to demonstrate practical experience with:

- Security alert investigation
- Log analysis
- Process tree analysis
- Timeline reconstruction
- MITRE ATT&CK mapping
- Incident documentation

---

# Investigation Methodology

Each incident investigation follows a structured workflow similar to real Security Operations Center procedures.

### Investigation Steps

1. Alert triggered in Splunk
2. Analyst reviews relevant logs
3. Identify affected host and user
4. Analyze process execution chain
5. Map behavior to MITRE ATT&CK techniques
6. Determine severity and impact
7. Document findings in an incident report

---

# Example Incident

### Encoded PowerShell Execution

Detection Source  
Splunk SIEM (Sysmon Event ID 1)

Technique  
PowerShell Execution using Base64 encoded commands

MITRE ATT&CK  
T1059.001 – Command and Scripting Interpreter: PowerShell

Summary  
A PowerShell command executed using the **EncodedCommand parameter** was detected.  
The encoded payload launched **calc.exe**, simulating a malicious PowerShell execution technique commonly used in fileless malware attacks.

Process Chain

cmd.exe  
→ powershell.exe  
→ calc.exe

---

# Purpose of These Reports

These investigation reports demonstrate the ability to:

- Perform security event triage
- Analyze endpoint telemetry
- Investigate suspicious process activity
- Document incidents clearly and professionally

This documentation reflects the type of investigation and reporting performed by **SOC analysts during real security incidents**.