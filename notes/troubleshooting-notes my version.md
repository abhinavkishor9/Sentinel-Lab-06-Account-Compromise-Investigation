# Troubleshooting Notes

## Issue 1 — Persistent Authentication Telemetry Was Unavailable

### Problem

The Sentinel workspace did not contain the persistent identity telemetry required for this account compromise investigation.

### Resolution

Synthetic authentication events were created using KQL `datatable()`.

This allowed the investigation to reproduce the required authentication sequence without presenting synthetic events as real Entra data.

---

## Issue 2 — Persistent Endpoint Telemetry Was Unavailable

### Problem

The workspace did not contain the endpoint process telemetry required to investigate activity following the authentication event.

### Resolution

Synthetic endpoint process data was created with KQL `datatable()`.

The dataset included:

- Time
- Computer
- User
- Parent process
- Process
- Command line

---

## Issue 3 — Synthetic Data Is Temporary

### Problem

KQL `datatable()` does not create a permanent Sentinel table.

### Resolution

Each query that requires the synthetic dataset must define the relevant data again.

This limitation was explicitly documented rather than treating the synthetic events as persistent telemetry.

---

## Issue 4 — The Failed-Login Pattern Is Not Password Spraying

### Observation

The source `185.220.101.10` produced:

**4 failed attempts against 1 user**

### Resolution

The result was not classified as confirmed password spraying.

Because the query was filtered to `user1`, the dataset does not demonstrate multiple targeted users.

The evidence is therefore limited to repeated failed authentication against one account.

---

## Issue 5 — Successful Login After Failures

### Observation

The same source produced four failures followed by a success.

### Resolution

This was treated as a suspicious authentication sequence.

It was not treated as automatic proof that the account had been compromised.

---

## Issue 6 — Location Change Requires Context

### Observation

Successful authentication occurred from:

    Hyderabad
    New York

### Resolution

The location change was treated as an anomaly.

Potential explanations such as VPNs, proxies, remote access, and inaccurate IP geolocation were documented.

---

## Issue 7 — Different User Formats

### Problem

The authentication data identifies the user as:

    user1@sentinellab.local

The endpoint data identifies the user as:

    user1

### Resolution

The two values were manually correlated as the same synthetic account.

In a production environment, normalized identity fields or stable account identifiers should be used for reliable correlation.

---

## Issue 8 — PowerShell Activity Alone Is Not Proof of Compromise

### Problem

PowerShell is a legitimate administration tool.

### Resolution

The investigation did not rely on `powershell.exe` alone.

It considered:

- Parent process.
- Command-line parameters.
- User.
- Computer.
- Authentication history.
- Timing.

The combined context provided stronger evidence for investigation.

---

## Issue 9 — Temporal Correlation Does Not Prove Causation

### Observation

The suspicious endpoint event occurred six minutes after successful authentication.

### Resolution

The six-minute interval was treated as a correlation signal.

It was not interpreted as proof that the authentication directly caused the endpoint activity.

---

## Issue 10 — No Evidence of Impact

### Problem

The synthetic endpoint data does not include network, file, child-process, or security-alert information.

### Resolution

These were recorded as evidence gaps.

The investigation did not invent payload execution, persistence, lateral movement, or data exfiltration.

---
