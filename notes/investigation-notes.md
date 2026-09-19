# Investigation Notes — Sentinel Lab 10

## Investigation Overview

**Investigation Type:** Threat Hunt — Internal Reconnaissance  
**Platform:** Microsoft Sentinel  
**Data Source:** Synthetic KQL `datatable()`  
**Primary Host:** `DESKTOP-LAB01`  
**Primary User:** `user1`

---

## Hunting Question

Does the endpoint telemetry show a concentrated sequence of discovery activity that could represent internal reconnaissance?

---

## Evidence Reviewed

The hunt examined:

- Process execution.
- Command lines.
- Users.
- Computers.
- Parent processes.
- Event timing.
- Frequency of discovery commands.

---

## Initial Process Review

The synthetic dataset contained activity from:

    DESKTOP-LAB01
    DESKTOP-LAB02

The initial review showed several command-line events associated with both systems.

---

## Discovery Command Hunt

The hunt searched for:

    ipconfig
    whoami
    netstat
    arp -a
    Get-Service

These commands were selected as discovery-related hunting indicators for the synthetic dataset.

---

## Primary Host Analysis

`DESKTOP-LAB01` showed the following sequence:

| Order | User | Parent Process | Process | Command |
|---|---|---|---|---|
| 1 | user1 | `explorer.exe` | `cmd.exe` | `ipconfig` |
| 2 | user1 | `explorer.exe` | `cmd.exe` | `whoami` |
| 3 | user1 | `explorer.exe` | `cmd.exe` | `netstat -ano` |
| 4 | user1 | `explorer.exe` | `powershell.exe` | `Get-Service` |
| 5 | user1 | `explorer.exe` | `cmd.exe` | `arp -a` |

The sequence was observed on the same host and under the same user context. :contentReference[oaicite:9]{index=9}

---

## Activity Concentration

The summary query produced:

| Computer | User | Recon Commands |
|---|---|---:|
| `DESKTOP-LAB01` | `user1` | 5 |
| `DESKTOP-LAB02` | `user2` | 2 |

The primary host therefore generated more discovery activity than the comparison host. :contentReference[oaicite:10]{index=10}

---

## Time Analysis

For `DESKTOP-LAB01`, the observed event window covered approximately four minutes.

The commands were executed in a tightly grouped sequence rather than appearing as isolated events. :contentReference[oaicite:11]{index=11}

---

## Comparison Host

`DESKTOP-LAB02` showed:

    ipconfig
    Get-Service

The two events were separated by approximately 15 minutes. :contentReference[oaicite:12]{index=12}

This provides comparison context for the much denser activity on `DESKTOP-LAB01`.

---

## Parent Process Analysis

The five primary events on `DESKTOP-LAB01` were associated with:

    explorer.exe

The child processes included:

    cmd.exe
    powershell.exe

The consistent parent process provides useful context but does not determine malicious intent. :contentReference[oaicite:13]{index=13}

---

## Hunt Threshold

The hunting query used:

    ReconCount >= 4

This returned:

    DESKTOP-LAB01
    ReconCount = 5
    User = user1

The threshold is specific to the synthetic training dataset and should not be treated as a production standard. :contentReference[oaicite:14]{index=14}

---

## Primary Finding

The strongest finding was:

    DESKTOP-LAB01
    user1
    5 discovery-related commands
    approximately 4-minute activity window

The sequence included:

    ipconfig
    whoami
    netstat -ano
    Get-Service
    arp -a

The commands cover multiple discovery categories and occurred in close succession.

---

## Evidence Classification

### Confirmed

- Five discovery-related commands were observed.
- All five were associated with `user1`.
- All five occurred on `DESKTOP-LAB01`.
- The events were concentrated within a short time period.
- Multiple discovery categories were represented.
- The hunt threshold of four commands was exceeded.

### Plausible

- The activity may represent internal reconnaissance.
- The commands may be part of a broader discovery phase.

### Unknown

- Whether the activity was malicious.
- Whether the activity was authorized.
- Whether the user was troubleshooting the system.
- Whether other systems were discovered.
- Whether lateral movement followed.
- Whether the endpoint was compromised.

---

## Hunting Assessment

**Suspicious — Possible Internal Reconnaissance**

The observed behavior warrants additional investigation, but the available telemetry does not establish malicious intent.

---

## Recommended Follow-Up

Review:

1. DNS queries.
2. Network connections.
3. Remote authentication.
4. SMB and administrative share activity.
5. Additional process creation.
6. PowerShell logging.
7. Activity against other endpoints.
8. Security alerts associated with the host.
9. User or administrator authorization.

---

## Key Lesson

The investigation became more meaningful when several discovery commands were considered together.

The core hunting pattern was:

**Same host + same user + multiple discovery actions + short time window**

This is stronger than treating a single discovery command as a standalone alert.
