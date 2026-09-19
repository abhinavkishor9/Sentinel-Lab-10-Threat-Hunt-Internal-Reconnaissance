# Troubleshooting Notes

## Issue 1 — Incomplete KQL Pipeline

### Problem

The following query fragment was initially used:

    | project TimeGenerated, Computer, User, ParentProcess, Process, CommandLine
    | order by TimeGenerated asc

Sentinel returned an error because the query began with a pipe and did not contain a tabular expression before it.

### Resolution

The complete `datatable()` source was placed before the pipeline.

The working structure became:

    datatable(...)
    | extend ...
    | project ...
    | order by ...

This provided Sentinel with a valid tabular source.

---

## Issue 2 — Synthetic Data Must Be Defined Again

### Problem

The process dataset was created with `datatable()`.

The synthetic table does not persist between separate KQL queries.

### Resolution

Each independent query was written with the required `datatable()` definition.

This ensured that each hunt query was self-contained and reproducible.

---

## Issue 3 — Timestamps Changed Between Queries

### Observation

The synthetic dataset used:

    TimeGenerated = now() - EventOffset

Different screenshots show different absolute timestamps for the same relative events.

For example, the `DESKTOP-LAB01` sequence appears at different clock times across separate query runs. :contentReference[oaicite:15]{index=15} :contentReference[oaicite:16]{index=16}

### Reason

`now()` is evaluated when each query is executed.

Since the queries were run at different times, the resulting absolute timestamps shifted.

### Resolution

The investigation used the relative offsets and event order as the primary evidence.

This is the correct approach for dynamically generated training telemetry.

---

## Issue 4 — ReconCount Threshold

### Observation

The hunt used:

    ReconCount >= 4

The query returned:

    DESKTOP-LAB01
    ReconCount = 5

### Resolution

The threshold was retained as a training threshold for this synthetic dataset.

It was documented as a lab-specific value rather than a universal detection standard. :contentReference[oaicite:17]{index=17}

---

## Issue 5 — Single Discovery Commands Are Not Automatically Suspicious

### Problem

Commands such as:

    ipconfig
    whoami

are commonly used during legitimate administration and troubleshooting.

### Resolution

The hunt focused on clustered behavior rather than individual commands.

The combination of five discovery-related commands on one host provided the stronger investigation lead.

---

## Issue 6 — Get-Service as Part of the Discovery Hunt

### Observation

The synthetic hunt included:

    powershell.exe -NoProfile -Command Get-Service

### Resolution

`Get-Service` was included as a service-discovery-related activity within this lab's hunting logic.

The command was evaluated in combination with the other discovery actions rather than treated as inherently suspicious.

---

## Issue 7 — Comparison Activity

### Observation

`DESKTOP-LAB02` showed:

    ipconfig
    Get-Service

### Resolution

The second endpoint was retained as comparison context.

Its lower activity count helped demonstrate how aggregation can distinguish a concentrated behavioral sequence from isolated discovery events. :contentReference[oaicite:18]{index=18}

---

## Issue 8 — Parent Process Context

### Observation

The primary events were associated with:

    explorer.exe

as the parent process.

### Resolution

The parent process was documented as contextual evidence.

It was not used as an independent maliciousness indicator because the available telemetry did not establish anything abnormal about the parent process. :contentReference[oaicite:19]{index=19}

---

## Issue 9 — No Follow-On Evidence

### Problem

The synthetic dataset did not include:

- DNS activity.
- Network connections.
- Remote authentication.
- SMB activity.
- Lateral movement.
- Endpoint alerts.

### Resolution

These were documented as evidence gaps.

No follow-on activity was assumed or fabricated.

---

