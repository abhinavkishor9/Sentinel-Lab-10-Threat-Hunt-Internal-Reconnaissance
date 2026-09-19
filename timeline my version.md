# Timeline 

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

