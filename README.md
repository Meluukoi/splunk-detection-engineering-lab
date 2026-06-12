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

### Notepad Execution Detection

![Notepad Detection](screenshots/notepad-detection.png)

### PowerShell Execution Detection

PowerShell activity identified through Sysmon Process Creation events. The investigation shows PowerShell spawning the `whoami.exe` process, providing visibility into command execution and parent-child process relationships.

![PowerShell Detection](screenshots/powershell-detection.png)


# Detection Scenario 2: Network Connection Monitoring

## Objective

Detect and investigate outbound network connections using Sysmon Event ID 3.

## Detection Query

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
"<EventID>3</EventID>"
```

## Investigation

Network connection events were successfully collected and indexed into Splunk.

Testing was performed by generating outbound network activity using web browsing and DNS lookups. Sysmon Event ID 3 telemetry was reviewed to identify:

- Source IP addresses
- Destination IP addresses
- Destination ports
- Destination hostnames
- Associated processes

The investigation confirmed successful collection of network connection events and demonstrated visibility into process-level network activity.

This visibility helps identify suspicious communications and potential command-and-control activity.

## MITRE ATT&CK Mapping

| Technique | ID |
|------------|------------|
| Application Layer Protocol | T1071 |
| Network Service Discovery | T1046 |

## Screenshots

### Network Connection Events

Network connection activity captured through Sysmon Event ID 3. The investigation identified outbound connections, destination IP addresses, destination hostnames, destination ports, and the originating process.

![Network Connection](screenshots/network-connection.png)
