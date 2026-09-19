# Timeline — Sentinel Lab 10

## Investigation Timeline

| Stage | Activity | Result |
|---|---|---|
| 09:00 | Synthetic endpoint telemetry created | Process dataset available |
| 09:05 | Initial KQL pipeline tested | Missing tabular source identified |
| 09:10 | Complete `datatable()` query tested | Query executed successfully |
| 09:15 | Full process activity reviewed | Multiple endpoints and users observed |
| 09:20 | Discovery commands filtered | Discovery-related activity isolated |
| 09:25 | `DESKTOP-LAB01` investigated | Five discovery commands identified |
| 09:30 | Command sequence reviewed | Multiple discovery categories observed |
| 09:35 | Activity summarized by host and user | `DESKTOP-LAB01` / `user1` had 5 events |
| 09:40 | Activity window analyzed | Approximately 4-minute cluster |
| 09:45 | `DESKTOP-LAB02` reviewed | Two comparison events identified |
| 09:50 | Parent processes reviewed | `explorer.exe` observed as parent |
| 09:55 | Hunt threshold applied | `ReconCount >= 4` returned `DESKTOP-LAB01` |
| 10:00 | Evidence classified | Suspicious pattern identified |
| 10:05 | Evidence gaps reviewed | Follow-on telemetry unavailable |
| 10:10 | Final hunting assessment assigned | Possible internal reconnaissance |

---

## Primary Event Sequence

    user1
    DESKTOP-LAB01

    ↓

    ipconfig

    ↓

    whoami

    ↓

    netstat -ano

    ↓

    Get-Service

    ↓

    arp -a

The five discovery-related events were observed within approximately four minutes. :contentReference[oaicite:20]{index=20} :contentReference[oaicite:21]{index=21}

---

## Comparison Activity

### DESKTOP-LAB02

    user2
    ↓
    ipconfig

    ↓ approximately 15 minutes

    Get-Service

This endpoint generated two discovery-related events compared with five on `DESKTOP-LAB01`. :contentReference[oaicite:22]{index=22}

---

## Investigation Milestones

### Initial Query Validation

The first query attempt failed because the pipeline did not contain a tabular source.

### Synthetic Dataset Validation

The complete `datatable()` query successfully produced the endpoint events.

### Discovery Hunt

The hunt identified commands associated with network, identity, connection, and service discovery.

### Primary Host Identified

`DESKTOP-LAB01` generated the highest number of discovery-related events.

### Behavioral Clustering

Five discovery actions occurred in a short period under the same user.

### Threshold Analysis

The `ReconCount >= 4` condition returned:

    DESKTOP-LAB01
    user1
    ReconCount = 5

:contentReference[oaicite:23]{index=23}

### Evidence Assessment

The activity was considered suspicious, but malicious intent remained unconfirmed.

---

## Evidence Summary

| Evidence | Status |
|---|---|
| Five discovery-related events on `DESKTOP-LAB01` | Confirmed |
| Same user across the sequence | Confirmed |
| Short activity window | Confirmed |
| Multiple discovery categories | Confirmed |
| `ReconCount` of 5 | Confirmed |
| Comparison activity on `DESKTOP-LAB02` | Confirmed |
| Internal reconnaissance | Plausible |
| Malicious intent | Unknown |
| Lateral movement | Unknown |
| Compromise | Unknown |

---

## Final Assessment

**Verdict:** Suspicious — Possible Internal Reconnaissance

**Primary Host:** `DESKTOP-LAB01`

**Primary User:** `user1`

**Recon Count:** `5`

**Activity Window:** Approximately 4 minutes

**Detection Threshold:**

    ReconCount >= 4

**Primary Evidence:**

    ipconfig
    whoami
    netstat -ano
    Get-Service
    arp -a

**Evidence Gap:**

No DNS, network, remote-authentication, SMB, lateral-movement, or endpoint-security telemetry was available.

**Final SOC Principle:**

> **Hunt for behavioral patterns, validate the context, and do not treat individual discovery commands as proof of malicious activity.**
