# Sentinel-Lab-06-Account-Compromise-Investigation
## Overview

An account compromise investigation examines whether authentication activity, endpoint behavior, and other available evidence together indicate that a user account may have been taken over.

The investigation should not assume compromise from a single event. Instead, the analyst builds an evidence chain around:

Successful and failed authentication activity.
Unusual source IPs or locations.
Authentication timing and frequency.
Endpoint activity after authentication.
Suspicious PowerShell or process execution.
Relationship between identity and endpoint events.
Evidence gaps and alternative explanations.

This lab investigates a potential account compromise by correlating authentication anomalies with subsequent endpoint activity.

The investigation begins with the authentication history of `user1@sentinellab.local`, where a normal successful sign-in is followed by repeated failed authentication attempts from another source IP and then a successful authentication from that source.

The investigation then examines endpoint activity associated with the same user and computer to determine whether suspicious activity followed the authentication event.

> **Investigation principle:** Build the incident timeline from evidence rather than assuming compromise from a single indicator.

---

## Investigation Scenario

A SOC analyst is investigating a user account after an unusual sequence of authentication events is observed. The account records several failed authentication attempts from the same source IP, followed shortly by a successful authentication from that source.

The investigation then shifts to the associated Windows endpoint to determine what happened after the successful sign-in. Suspicious PowerShell activity is identified on the same host, creating a potential relationship between the identity event and endpoint activity.

The analyst focuses on:

- Repeated authentication failures from the same source.
- A subsequent successful authentication.
- Changes in source IP and authentication location.
- Endpoint activity following the successful sign-in.
- The relationship between the user, host, and event timestamps.
- Suspicious PowerShell execution involving `winword.exe`.

The key sequence shows authentication activity followed **six minutes later** by PowerShell execution on `DESKTOP-LAB01`. The available evidence must be examined as a complete timeline rather than as isolated alerts.

The objective is to determine whether the combined activity is consistent with a **possible account compromise**, while clearly separating confirmed evidence from assumptions and identifying what additional telemetry would be required for confirmation.

---

## Lab Objectives

The objectives of this lab are to:

- Examine authentication activity for signs of unusual account behavior.
- Identify repeated authentication failures and the source associated with them.
- Determine whether a previously failing source later achieved successful authentication.
- Compare successful authentication locations and source IP addresses.
- Trace endpoint activity occurring after the suspicious authentication.
- Connect identity and endpoint evidence through user, host, and timestamp correlation.
- Evaluate the significance of suspicious PowerShell execution in the broader account activity.
- Build a chronological sequence of events from the available telemetry.
- Distinguish confirmed observations from plausible relationships and unknown conditions.
- Identify additional evidence needed to validate suspected account compromise and determine impact.

---

## Environment

| Component | Details |
|---|---|
| Platform | Microsoft Sentinel |
| Workspace | `Microsoft-Sentinel-Workspace` |
| Query Language | KQL |
| Data Type | Synthetic telemetry |
| Primary User | `user1@sentinellab.local` |
| Primary Host | `DESKTOP-LAB01` |
| Investigation Date | 2026-09-16 |

---

## Data Source

Persistent authentication and endpoint telemetry was not available for this investigation.

Synthetic authentication and process data was therefore created using KQL `datatable()`.

The synthetic datasets are temporary and exist only within the queries where they are defined. They are used for investigation and detection-learning purposes and do not represent production telemetry.

---

## Investigation Workflow

The investigation followed these stages:

1. Review the user's authentication history.
2. Identify failed authentication activity.
3. Determine whether the suspicious source later succeeded.
4. Review successful sign-in locations and IP addresses.
5. Review endpoint activity for the associated computer.
6. Identify suspicious PowerShell execution.
7. Correlate authentication and endpoint events.
8. Build the incident timeline.
9. Assess confirmed and unknown evidence.
10. Assign an evidence-based verdict.

---

## Step 1 — Review the User's Authentication History

The authentication activity for `user1@sentinellab.local` was reviewed in chronological order.

The observed sequence was:

| Time UTC | IP Address | Result | Location |
|---|---|---|---|
| 09:00 | `10.10.10.25` | Success | Hyderabad |
| 09:02 | `185.220.101.10` | Failed | Unknown |
| 09:03 | `185.220.101.10` | Failed | Unknown |
| 09:04 | `185.220.101.10` | Failed | Unknown |
| 09:05 | `185.220.101.10` | Failed | Unknown |
| 09:06 | `185.220.101.10` | Success | New York |

This sequence shows repeated failures followed by a successful authentication from the same source.

---

## Step 2 — Review Failed Authentication Activity

The following analysis was used to count failed authentication attempts by source IP:

    | where UserPrincipalName == "user1@sentinellab.local"
    | where ResultType != 0
    | summarize
        FailedAttempts = count(),
        TargetedUsers = dcount(UserPrincipalName)
        by IPAddress
    | order by FailedAttempts desc

### Observed Result

| IP Address | Failed Attempts | Targeted Users |
|---|---:|---:|
| `185.220.101.10` | 4 | 1 |

The source generated four failed authentication attempts against `user1`.

Because the query is filtered to a single user, `TargetedUsers = 1` does not establish password spraying across multiple accounts.

---

## Step 3 — Check for Successful Authentication

The same source IP was then reviewed to determine whether authentication eventually succeeded.

The result showed:

    09:02 — Failed
    09:03 — Failed
    09:04 — Failed
    09:05 — Failed
    09:06 — Success

The transition from repeated failures to a successful authentication is an important investigation point.

It does not, by itself, prove that the account was compromised.

---

## Step 4 — Review Successful Sign-ins

The successful sign-ins for `user1` were summarized.

Observed result:

| User | Successful Sign-ins | Locations | IP Addresses |
|---|---:|---|---|
| `user1@sentinellab.local` | 2 | Hyderabad, New York | `10.10.10.25`, `185.220.101.10` |

The account therefore had successful authentication from two different locations during the dataset timeframe.

---

## Step 5 — Review Endpoint Activity

The endpoint dataset was reviewed for process execution.

The observed PowerShell activity included:

| Time UTC | Computer | User | Parent Process | Process |
|---|---|---|---|---|
| 09:12 | `DESKTOP-LAB01` | `user1` | `winword.exe` | `powershell.exe` |
| 13:00 | `DESKTOP-LAB02` | `user2` | `explorer.exe` | `powershell.exe` |

The `user1` event was selected for further investigation.

---

## Step 6 — Analyze the Suspicious PowerShell Event

The primary endpoint event occurred at:

**2026-09-16 09:12 UTC**

Observed command line:

    powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBtAHAAMwByAHQAYQBuAHQAPQ=

Observed context:

| Field | Value |
|---|---|
| User | `user1` |
| Computer | `DESKTOP-LAB01` |
| Parent Process | `winword.exe` |
| Process | `powershell.exe` |
| Parameters | `-ExecutionPolicy Bypass` and `-EncodedCommand` |

The event contains multiple characteristics that warrant further investigation.

---

## Step 7 — Correlate Authentication and Endpoint Activity

The suspicious authentication event occurred at:

**09:06 UTC**

The suspicious PowerShell event occurred at:

**09:12 UTC**

Time difference:

**6 minutes**

The events also share the same user and endpoint context:

    user1
    DESKTOP-LAB01

The resulting sequence is:

    Failed authentication attempts
              ↓
    Successful authentication
              ↓
    6 minutes
              ↓
    winword.exe → powershell.exe
              ↓
    ExecutionPolicy Bypass
              ↓
    EncodedCommand

This provides a meaningful correlation for continued investigation.

---

## Primary Finding

The strongest evidence chain is:

    09:02–09:05
    Four failed authentication attempts
    185.220.101.10

              ↓

    09:06
    Successful authentication
    185.220.101.10
    New York

              ↓ 6 minutes

    09:12
    user1 / DESKTOP-LAB01
    winword.exe → powershell.exe
    -ExecutionPolicy Bypass
    -EncodedCommand

This sequence is suspicious and is consistent with a possible account compromise scenario.

---

## Investigation Verdict

**Verdict: Suspicious — Possible Account Compromise**

The available evidence supports further investigation of the account and endpoint.

However, the synthetic telemetry does not prove that the account was compromised or that the successful authentication was unauthorized.

---

## Evidence Assessment

| Evidence | Assessment |
|---|---|
| Four failed authentication attempts | Confirmed |
| Same source later authenticated successfully | Confirmed |
| Successful sign-in from New York | Confirmed |
| Successful sign-in from Hyderabad also observed | Confirmed |
| Endpoint activity associated with user1 | Confirmed |
| PowerShell launched by `winword.exe` | Confirmed |
| `-ExecutionPolicy Bypass` present | Confirmed |
| `-EncodedCommand` present | Confirmed |
| Six-minute authentication-to-endpoint interval | Confirmed |
| Authentication was unauthorized | Unknown |
| PowerShell activity was malicious | Unknown |
| Account compromise | Unknown |
| Payload execution or impact | Unknown |

---

## False-Positive Considerations

Potential legitimate explanations should still be considered:

- VPN or proxy infrastructure.
- Incorrect IP geolocation.
- Legitimate remote access.
- Authorized administrative activity.
- Enterprise automation.
- User activity from a different location.
- Security testing.

These possibilities do not automatically explain the entire sequence, so they should be validated against additional telemetry.

---

## Evidence Gaps

The investigation did not contain:

- MFA results.
- Conditional Access decisions.
- Sign-in risk information.
- Authentication method.
- Device identity or compliance.
- PowerShell Script Block Logging.
- Child-process activity.
- Network connections.
- File creation or modification.
- Endpoint security alerts.
- Decoded command content.
- User confirmation of the authentication.

---

## MITRE ATT&CK

**T1059.001 — Command and Scripting Interpreter: PowerShell**

The endpoint evidence involves PowerShell execution.

The ATT&CK mapping describes the execution mechanism observed in the telemetry and does not independently establish malicious activity.

---

