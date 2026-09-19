# Sentinel Lab 10 — Threat Hunt: Internal Reconnaissance

## Overview

This lab performs a proactive threat hunt for **internal reconnaissance activity** using Microsoft Sentinel and KQL.

Unlike an alert-driven investigation, the hunt begins with a behavioral hypothesis and searches endpoint telemetry for related discovery commands. The objective is to determine whether multiple discovery actions are concentrated on the same host and user within a short period.

> **Hunting principle:** Look for the pattern, not just the individual command.

---

## Investigation Scenario

A Windows environment contains process execution telemetry from multiple users and endpoints.

One endpoint, `DESKTOP-LAB01`, shows several discovery-related commands executed by `user1` within a short period. A second endpoint, `DESKTOP-LAB02`, contains a smaller amount of comparable activity from `user2`.

The hunt investigates whether the concentration of commands on `DESKTOP-LAB01` is consistent with possible internal reconnaissance.

---

## Lab Objectives

- Perform a proactive hunt for discovery activity.
- Identify common reconnaissance-related commands.
- Review process, user, host, and command-line context.
- Measure the concentration of discovery activity on individual hosts.
- Compare activity between users and endpoints.
- Use KQL aggregation to identify hosts with multiple discovery actions.
- Determine whether clustered discovery behavior warrants investigation.
- Distinguish suspicious reconnaissance from normal administrative activity.

---

## Environment

| Component | Details |
|---|---|
| Platform | Microsoft Sentinel |
| Workspace | `Microsoft-Sentinel-Workspace` |
| Query Language | KQL |
| Data Type | Synthetic telemetry |
| Primary Host | `DESKTOP-LAB01` |
| Primary User | `user1` |
| Comparison Host | `DESKTOP-LAB02` |
| Comparison User | `user2` |

---

## Data Source

Persistent endpoint telemetry was not available for this hunt.

Synthetic process execution data was therefore created using KQL `datatable()`.

The dataset contains:

- `EventOffset`
- `Computer`
- `User`
- `ParentProcess`
- `Process`
- `CommandLine`

`TimeGenerated` is created dynamically using `now() - EventOffset`.

Because the timestamps are generated relative to the time each query is executed, absolute timestamps can shift between separate query runs. The event order and relative offsets remain the important evidence for the hunt.

---

## Investigation Workflow

The hunt followed these stages:

1. Review all process execution activity.
2. Identify discovery-related commands.
3. Focus on the primary host.
4. Analyze the command sequence.
5. Count discovery activity by host and user.
6. Establish the activity window.
7. Compare against another endpoint.
8. Build a detection-oriented hunting query.
9. Assess whether the pattern is suspicious.
10. Document limitations and possible legitimate explanations.

---

## Step 1 — Review Process Activity

The initial query displayed:

- Time
- Computer
- User
- Parent process
- Process
- Command line

The dataset showed activity from `DESKTOP-LAB01` and `DESKTOP-LAB02`.

---

## Step 2 — Identify Discovery Commands

The hunt searched for command-line content associated with discovery behavior, including:

    ipconfig
    whoami
    netstat
    arp -a
    Get-Service

These commands represent different types of host, identity, network, and service discovery.

A single discovery command is not enough to conclude malicious activity.

---

## Step 3 — Investigate DESKTOP-LAB01

The primary host was filtered and reviewed separately.

Observed sequence:

| Order | User | Process | Command |
|---|---|---|---|
| 1 | user1 | `cmd.exe` | `ipconfig` |
| 2 | user1 | `cmd.exe` | `whoami` |
| 3 | user1 | `cmd.exe` | `netstat -ano` |
| 4 | user1 | `powershell.exe` | `Get-Service` |
| 5 | user1 | `cmd.exe` | `arp -a` |

All five events were associated with:

`DESKTOP-LAB01`

and:

`user1`

The sequence was observed over a short period. :contentReference[oaicite:2]{index=2}

---

## Step 4 — Count Reconnaissance Activity

The hunt summarized discovery commands by host and user.

Observed results:

| Computer | User | Recon Commands |
|---|---|---:|
| `DESKTOP-LAB01` | `user1` | 5 |
| `DESKTOP-LAB02` | `user2` | 2 |

`DESKTOP-LAB01` therefore showed the highest concentration of discovery activity. :contentReference[oaicite:3]{index=3}

---

## Step 5 — Examine the Activity Window

For `DESKTOP-LAB01`, the five events occurred within approximately **four minutes**.

This clustering is important because the commands cover multiple discovery categories in a short period. :contentReference[oaicite:4]{index=4}

---

## Step 6 — Compare With DESKTOP-LAB02

`DESKTOP-LAB02` showed only two discovery-related events:

    ipconfig
    Get-Service

These events were separated by a longer interval and did not show the same concentration as the activity on `DESKTOP-LAB01`. :contentReference[oaicite:5]{index=5}

The comparison provides context rather than proving that the second endpoint is benign.

---

## Step 7 — Analyze the Process Context

All five primary events on `DESKTOP-LAB01` were launched from:

    explorer.exe

The activity therefore showed a consistent parent process while the commands themselves represented different discovery actions. :contentReference[oaicite:6]{index=6}

The parent process alone does not determine whether the activity is malicious.

---

## Step 8 — Build the Hunt Logic

The hunt used a threshold of:

    ReconCount >= 4

The query returned:

| Computer | Recon Count | User |
|---|---:|---|
| `DESKTOP-LAB01` | 5 | `user1` |

This successfully isolated the endpoint with concentrated discovery behavior. :contentReference[oaicite:7]{index=7} :contentReference[oaicite:8]{index=8}

The threshold is a **training value** for this synthetic dataset and should not be treated as a universal production threshold.

---

## Primary Finding

`DESKTOP-LAB01` generated five discovery-related commands from `user1` within approximately four minutes:

    ipconfig
    whoami
    netstat -ano
    Get-Service
    arp -a

The commands cover several areas of system and network discovery.

The concentration of multiple discovery behaviors makes the host the primary hunting lead.

---

## Hunting Assessment

**Assessment: Suspicious — Possible Internal Reconnaissance**

The observed behavior is consistent with an internal reconnaissance pattern.

However, the available synthetic telemetry does not establish malicious intent.

---

## Evidence Assessment

| Evidence | Assessment |
|---|---|
| Five discovery-style commands on `DESKTOP-LAB01` | Confirmed |
| All associated with `user1` | Confirmed |
| Multiple discovery categories represented | Confirmed |
| Activity clustered in a short period | Confirmed |
| `DESKTOP-LAB02` showed lower activity | Confirmed |
| Internal reconnaissance | Plausible |
| Malicious intent | Unknown |
| Unauthorized activity | Unknown |
| Lateral movement | Unknown |
| Compromise | Unknown |

---

## False-Positive Considerations

Possible legitimate explanations include:

- IT troubleshooting.
- Network diagnostics.
- System administration.
- Security testing.
- Incident-response activity.
- Authorized support scripts.

The commands should therefore be interpreted together with the user, host, timing, and surrounding activity.

---

## Evidence Gaps

The synthetic telemetry does not show:

- Network connections generated by the commands.
- DNS activity.
- Remote system access.
- SMB or administrative share activity.
- Authentication after the discovery sequence.
- PowerShell Script Block Logging.
- Child processes beyond the supplied process data.
- Endpoint security alerts.
- User authorization context.

---

## Key SOC Lesson

Internal reconnaissance is often better identified through **behavioral clustering** than through a single command.

The important pattern in this hunt was:

**Multiple discovery commands + same user + same host + short time window**

The presence of `ipconfig` or `whoami` alone would not justify the same level of attention.

---

## Lab Outcome

This hunt demonstrated how to:

- Search endpoint telemetry without relying on an existing alert.
- Identify discovery-related commands.
- Group activity by host and user.
- Measure discovery activity concentration.
- Compare primary and baseline behavior.
- Create threshold-based hunting logic.
- Separate suspicious behavior from confirmed malicious activity.

---

## Conclusion

The hunt identified `DESKTOP-LAB01` as the primary endpoint of interest after `user1` executed five discovery-related commands within approximately four minutes. The activity was more concentrated than the comparison activity on `DESKTOP-LAB02`.

The pattern is **suspicious and consistent with possible internal reconnaissance**, but the available synthetic telemetry does not establish malicious intent or compromise.
