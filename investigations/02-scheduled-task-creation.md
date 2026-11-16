# Scenario 2: Scheduled Task Persistence Detection

## Overview

This scenario demonstrates how Windows scheduled task creation can be monitored and detected using Wazuh.

Scheduled tasks are a legitimate Windows feature, but attackers can abuse them to establish persistence by configuring commands or programs to execute automatically at specific times or when a user logs in.

The objective was to generate a benign scheduled task, capture the resulting Windows Security event, and create a custom Wazuh rule to identify tasks configured with a logon trigger.

## MITRE ATT&CK Mapping

| Attribute | Details |
|---|---|
| Tactic | Persistence |
| Technique | T1053.005 – Scheduled Task |
| Event ID | 4698 – A scheduled task was created |
| Log source | Windows Security Event Log |
| Detection platform | Wazuh |

## Lab Environment

- **Target:** Windows 11
- **Wazuh agent:** Martha (`192.168.56.106`)
- **Wazuh manager:** Ubuntu Linux
- **Detection source:** Windows Security auditing
- **Event collection:** Windows Security channel

## 1. Simulation

Windows auditing for Other Object Access Events was enabled:

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable
```

A benign scheduled task was created using PowerShell:

```powershell
$Action = New-ScheduledTaskAction -Execute "notepad.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogOn

Register-ScheduledTask `
    -TaskName "WazuhLab-ScheduledTask-Validation" `
    -Action $Action `
    -Trigger $Trigger `
    -Description "Custom Wazuh rule validation" `
    -User "$env:USERDOMAIN\$env:USERNAME" `
    -RunLevel Limited `
    -Force
```

The task was configured to launch Notepad when the user logs in. This provided a safe simulation of logon-triggered scheduled task creation.

## 2. Event Collection and Initial Detection

Windows generated **Security Event ID 4698**, indicating that a scheduled task had been created.

Wazuh successfully collected the event and generated a built-in alert using rule `60228`:

- Description: A scheduled task was created.
- Event ID: 4698.
- Source: Microsoft-Windows-Security-Auditing.

## 3. Custom Detection Rule

A custom Wazuh rule was added to `local_rules.xml`:

```xml
<rule id="100300" level="8">
  <if_sid>60228</if_sid>
  <field name="win.eventdata.taskContent" type="pcre2">(?i)LogonTrigger</field>
  <description>Logon-triggered scheduled task created: $(win.eventdata.taskName)</description>
  <mitre>
    <id>T1053.005</id>
  </mitre>
  <group>persistence,scheduled_task,</group>
</rule>
```

### Detection logic

The custom rule:

1. Uses built-in rule `60228` as its parent, ensuring the underlying event represents scheduled task creation.
2. Examines the `taskContent` field for `LogonTrigger`.
3. Generates a higher-level alert when the condition is met.
4. Maps the detection to MITRE ATT&CK technique T1053.005.

## 4. Detection Validation

A second benign scheduled task was created to validate the custom detection.

Wazuh successfully generated an alert matching custom rule `100300`.

**Alert details:**

| Field | Observed value |
|---|---|
| Rule ID | 100300 |
| Alert level | 8 |
| Event ID | 4698 |
| Task name | WazuhLab-ScheduledTask-Validation |
| Account | CYBERLAB\Administrator |
| Trigger | LogonTrigger |
| Executable | notepad.exe |
| MITRE technique | T1053.005 |

### Evidence 1: Custom Wazuh Detection Alert

![Figure 1: Wazuh custom detection alert](https://github.com/user-attachments/assets/92fb3ddd-b29c-4453-9ee8-64143343959e)

*Figure 1: Wazuh successfully triggered custom rule 100300 at level 8.*

### Evidence 2: Expanded Event Details

![Figure 2: Expanded Wazuh event details](https://github.com/user-attachments/assets/158730b0-9581-48ee-a78c-1e3f29e455ab)

*Figure 2: Underlying Windows Security event showing the task name, account, logon trigger and executable.*

### Evidence 3: Custom Detection Rule

![Figure 3: Custom Wazuh rule in local_rules.xml](https://github.com/user-attachments/assets/62514e78-cb78-44b1-8f82-7af47977cb46)

*Figure 3: Custom Wazuh rule identifying scheduled tasks configured with a logon trigger.*

## 5. Outcome

The scenario successfully demonstrated an end-to-end detection workflow:

**Scheduled task creation → Windows Event ID 4698 → Wazuh built-in rule 60228 → Custom rule 100300.**

The custom rule successfully identified scheduled tasks configured with a logon trigger and generated a level 8 alert.

This exercise demonstrated the ability to:

- Configure Windows auditing.
- Collect and investigate Windows Security events through Wazuh.
- Understand built-in Wazuh rule relationships.
- Develop and validate custom detection rules.
- Map detections to the MITRE ATT&CK framework.

## 6. Limitations

This detection identifies scheduled task creation events containing a logon trigger. It does not identify every possible form of scheduled task abuse or establish that a task is malicious.

Additional detection logic and investigation context would be required to distinguish malicious scheduled tasks from legitimate administrative activity.
