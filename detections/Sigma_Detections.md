# Sigma Detection Rules

## SSH Brute Force

title: SSH Brute Force Detection logsource: product: linux service: sshd
detection: selection: message: "Failed password" condition: selection
level: high

## Suspicious PowerShell Execution

title: Suspicious PowerShell Execution logsource: product: windows
service: sysmon detection: selection: EventID: 1 Image\|contains:
powershell.exe condition: selection level: medium
