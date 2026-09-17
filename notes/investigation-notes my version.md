# Investigation Notes 

## Evidence Reviewed

The investigation examined:

- Successful authentication events.
- Failed authentication events.
- Source IP addresses.
- Authentication locations.
- Associated computer.
- PowerShell execution.
- Parent process.
- PowerShell command-line parameters.
- Time relationship between authentication and endpoint activity.

---

## Authentication Timeline

The observed authentication history for `user1@sentinellab.local` was:

| Time UTC | IP Address | Result | Location |
|---|---|---|---|
| 09:00 | `10.10.10.25` | Success | Hyderabad |
| 09:02 | `185.220.101.10` | Failed | Unknown |
| 09:03 | `185.220.101.10` | Failed | Unknown |
| 09:04 | `185.220.101.10` | Failed | Unknown |
| 09:05 | `185.220.101.10` | Failed | Unknown |
| 09:06 | `185.220.101.10` | Success | New York |

The sequence shows four failed attempts followed by a successful authentication from the same source IP.

---

## Failed Authentication Analysis

The failed authentication query returned:

| IP Address | Failed Attempts | Targeted Users |
|---|---:|---:|
| `185.220.101.10` | 4 | 1 |

The source made four failed attempts against the investigated account.

Because the query is scoped to `user1`, the result does not demonstrate activity against multiple users.

Therefore, this evidence should not be classified as confirmed password spraying.

---

## Successful Authentication Analysis

The same source later succeeded:

    09:02 — Failed
    09:03 — Failed
    09:04 — Failed
    09:05 — Failed
    09:06 — Success

This transition is suspicious and requires investigation.

The evidence confirms authentication behavior but does not establish the identity or intent of the actor behind the source IP.

---

## Location Analysis

Successful authentication for the account was observed from:

- Hyderabad
- New York

Associated source IPs:

- `10.10.10.25`
- `185.220.101.10`

The change in location is an anomaly within the synthetic dataset.

It should not be treated as proof of compromise because VPNs, proxies, remote access, and IP geolocation issues can produce similar observations.

---

## Endpoint Analysis

The endpoint dataset showed:

| Time UTC | Computer | User | Parent | Process |
|---|---|---|---|---|
| 09:12 | `DESKTOP-LAB01` | `user1` | `winword.exe` | `powershell.exe` |
| 13:00 | `DESKTOP-LAB02` | `user2` | `explorer.exe` | `powershell.exe` |

The `user1` event was selected as the primary endpoint finding.

---

## PowerShell Analysis

The command line observed for `user1` was:

    powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBtAHAAMwByAHQAYQBuAHQAPQ=

The event therefore contained:

- `powershell.exe`
- `-ExecutionPolicy Bypass`
- `-EncodedCommand`
- `winword.exe` as the parent process

These characteristics create a stronger suspicious signal than PowerShell execution alone.

---

## Identity and Endpoint Correlation

The successful authentication occurred at:

**09:06 UTC**

The endpoint activity occurred at:

**09:12 UTC**

Time difference:

**6 minutes**

Both events are associated with:

    user1
    DESKTOP-LAB01

This makes the events potentially related and forms the central correlation in the investigation.

---

## Incident Sequence

    09:00
    Successful authentication
    user1
    Hyderabad

    ↓

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
    user1
    DESKTOP-LAB01
    winword.exe → powershell.exe
    Bypass + EncodedCommand

---

## Evidence Classification

### Confirmed

- Four failed authentication attempts occurred.
- All four failures came from `185.220.101.10`.
- The same source later authenticated successfully.
- The successful authentication was associated with New York.
- The account also had a successful authentication from Hyderabad.
- PowerShell executed on `DESKTOP-LAB01`.
- `winword.exe` launched PowerShell.
- `-ExecutionPolicy Bypass` was present.
- `-EncodedCommand` was present.
- The endpoint event occurred six minutes after the successful authentication.

### Plausible

- The authentication and endpoint activity may be related.
- The activity may represent unauthorized use of the account.
- The sequence may be consistent with an account compromise.

### Unknown

- Whether the successful authentication was unauthorized.
- Whether the source IP was controlled by an attacker.
- Whether the account was actually compromised.
- Whether the PowerShell command was malicious.
- What the encoded command contained.
- Whether a payload executed successfully.
- Whether persistence was established.
- Whether data was accessed or exfiltrated.

---

## Investigation Verdict

**Suspicious — Possible Account Compromise**

The evidence supports escalation for additional investigation.

The available telemetry does not justify a confirmed-compromise conclusion.

---

