# Splunk Detection Engineering Lab

## Overview

This project focuses on detection engineering and threat hunting using Splunk Enterprise, Sysmon, and Windows Event Logs.

The objective is to create and validate detections for common attacker techniques while investigating security telemetry collected from Windows endpoints.

---

## Lab Environment

### Tools Used

- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon
- Windows Event Viewer
- Windows Command Prompt
- PowerShell

### Data Sources

- Microsoft-Windows-Sysmon/Operational
- Windows Security Logs
- Windows System Logs

---

## Detection Scenario 1: Process Creation Monitoring

### Objective

Detect and investigate newly created processes using Sysmon Event ID 1.

### Detection Query

``spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1

## Investigation

Process creation events were successfully indexed into Splunk.

Several processes were generated and validated, including:

- cmd.exe
- notepad.exe
- powershell.exe

These events provided visibility into process execution activity and parent-child process relationships.

---

## MITRE ATT&CK Mapping

| Technique | ID |
|------------|------------|
| Command and Scripting Interpreter | T1059 |
| PowerShell | T1059.001 |
| Windows Command Shell | T1059.003 |

---

## Screenshots

### Sysmon Process Creation Events

![Process Creation](screenshots/process-creation.png)

### CMD Execution Detection

![CMD Detection](screenshots/cmd-detection.png)

### PowerShell Detection

![PowerShell Detection](screenshots/powershell-detection.png)

### Notepad Execution Detection

![Notepad Detection](screenshots/notepad-detection.png)

