# Timeline — Sentinel Lab 06

## Investigation Timeline

| Time UTC | Activity | Result |
|---|---|---|
| 09:00 | user1 successful authentication | Hyderabad / `10.10.10.25` |
| 09:02 | Failed authentication | `185.220.101.10` |
| 09:03 | Failed authentication | `185.220.101.10` |
| 09:04 | Failed authentication | `185.220.101.10` |
| 09:05 | Failed authentication | `185.220.101.10` |
| 09:06 | Successful authentication | New York / `185.220.101.10` |
| 09:12 | PowerShell execution | `winword.exe` → `powershell.exe` |
| 09:15 | Identity and endpoint correlation | Same user and host |
| 09:20 | Evidence assessment | Suspicious sequence identified |
| 09:25 | Evidence gaps reviewed | Additional telemetry required |
| 09:30 | Final verdict assigned | Possible account compromise |

---

## Key Event Sequence

    09:00 UTC
    user1 successful authentication
    Hyderabad
    10.10.10.25
    DESKTOP-LAB01

    ↓

    09:02 UTC
    Failed authentication
    185.220.101.10

    ↓

    09:03 UTC
    Failed authentication
    185.220.101.10

    ↓

    09:04 UTC
    Failed authentication
    185.220.101.10

    ↓

    09:05 UTC
    Failed authentication
    185.220.101.10

    ↓

    09:06 UTC
    Successful authentication
    185.220.101.10
    New York
    DESKTOP-LAB01

    ↓ 6 minutes

    09:12 UTC
    user1
    DESKTOP-LAB01
    winword.exe → powershell.exe
    -ExecutionPolicy Bypass
    -EncodedCommand

---

## Investigation Milestones

### Authentication Review

The account initially authenticated successfully from Hyderabad.

### Failed Authentication Pattern

Four consecutive failures were observed from `185.220.101.10`.

### Authentication Success

The same source successfully authenticated at 09:06 UTC.

### Location Anomaly

The successful authentication from the suspicious source was associated with New York, while another successful authentication for the account was associated with Hyderabad.

### Endpoint Activity

Six minutes after the successful authentication, PowerShell was launched on `DESKTOP-LAB01`.

### Process Analysis

The PowerShell process was launched by `winword.exe` and contained:

    -ExecutionPolicy Bypass
    -EncodedCommand

### Cross-Source Correlation

The identity and endpoint events shared the same user and computer context.

### Evidence Assessment

The combined sequence was considered suspicious, but compromise remained unconfirmed.

---

## Evidence Summary

| Evidence | Status |
|---|---|
| Four failed logins from same source | Confirmed |
| Same source later succeeded | Confirmed |
| Successful login from New York | Confirmed |
| Successful login from Hyderabad | Confirmed |
| PowerShell execution | Confirmed |
| Word launched PowerShell | Confirmed |
| Bypass parameter | Confirmed |
| Encoded command parameter | Confirmed |
| Six-minute gap | Confirmed |
| Unauthorized authentication | Unknown |
| Account compromise | Unknown |
| Malicious payload | Unknown |

---

## Final Assessment

**Verdict:** Suspicious — Possible Account Compromise

**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

**Primary Evidence Chain:**

    Authentication failures
    →
    Successful authentication
    →
    New York
    →
    6 minutes
    →
    winword.exe → powershell.exe
    →
    Bypass + EncodedCommand

**Evidence Gap:**

No MFA, Conditional Access, sign-in risk, PowerShell Script Block, network, file, child-process, or endpoint-security telemetry was available.

**Final SOC Principle:**

> **Build the timeline from evidence, then assess the compromise hypothesis.**
