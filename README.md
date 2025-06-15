# Threat-Hunting-Scenario-Deep-Access-The-Adversary

**Participant:** Aaron Martinez

**Date:** June, 25 2025

## Platforms and Languages Leveraged

**Platforms:**

* Microsoft Defender for Endpoint (MDE)
* Log Analytics Workspace
* Windows 10-based system

**Languages/Tools:**

* Kusto Query Language (KQL) for querying device events, registry modifications, and persistence artifacts

---

## Scenario

For weeks, multiple partner organizations across Southeast Asia and Eastern Europe detected odd outbound activity to obscure cloud endpoints. Initially dismissed as harmless automation, the anomalies began aligning.

Across sectors — telecom, defense, manufacturing — analysts observed the same patterns: irregular PowerShell bursts, unexplained registry changes, and credential traces mimicking known red-team tools.

Then came a break. A tech firm flagged sensitive project files leaked days before a bid was undercut. An energy provider found zipped payloads posing as sync utilities in public directories.

Whispers grew — not one actor, but a coordinated effort. Code fragments matched across unrelated environments. The beaconing continued: quiet, rhythmic pings to endpoints no business could explain.

Some suspect Starlance — an old, disbanded joint op revived. Others say mercenary crews using supply chain access and familiar tooling.

What’s clear: this wasn’t smash-and-grab. It was long game.

Your task: trace the access, map the spread, and uncover what was touched — or taken. Two machines hold the truth, scattered and shrouded.

No alerts fired. No passwords changed.
But something was here…
…and it might return.

---

## Key Observations

* **Initial Vector:** A fake antivirus binary named `BitSentinelCore.exe` was dropped into `C:\ProgramData\`.
* **Dropper Used:** Legitimate Microsoft-signed binary `csc.exe` (C# compiler) was abused to compile and drop the malware.
* **Execution:** The malware was executed via PowerShell on **2025-05-07T02:00:36.794406Z**, marking the root of the malicious chain.
* **Keylogger:** A deceptive shortcut `systemreport.lnk` was dropped in the AppData folder to enable keystroke capture on logon.
* **Registry Persistence:** Auto-run registry key was created at:
  `HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
* **Scheduled Task:** Named `UpdateHealthTelemetry`, this ensured long-term execution of the malware.
* **Process Chain:** `BitSentinelCore.exe -> cmd.exe -> schtasks.exe`

---

## Threat Hunting Process

### Identifying the Beachhead
The key to filtering and narrowing down plausible devices that could have served as the beachhead for the attacker was understanding that the system used in the initial stage of the attack was briefly active around May 24, 2025. With the system being present in the network for a short amount of time, process activtiy logged by MDE should be less than normal in comparison to other devices on the network. I applied a filter to exlcude devices with first observed process events outside of the May 24 and May 25 range and then calculated the amount of hours each system had process activtiy occurring ('LifeTimeHours'). Ordering systems from the least amount of 'LifeTimeHours' to the most, I scanned device names to find any atypical names returned by the query.
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-05-24) .. datetime(2025-05-26))
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceId, DeviceName
| extend LifetimeHours = datetime_diff("hour", LastSeen, FirstSeen)
| where LifetimeHours > 0 and LifetimeHours <= 12
| project DeviceName, FirstSeen, LastSeen, LifetimeHours
```
![image](https://github.com/user-attachments/assets/fd97ce5a-0610-4ab6-a867-3c66b3b4f3e8)

![image](https://github.com/user-attachments/assets/b34e4e80-d3ee-4745-93e9-45f30b360555)

Having identified the suspicious system, I cross correlated the incidents reports within MDE around May 24th to see if any alerts had been flagged on the system. Sure enough, MDE had flagged the system for malicious activtiy being present on the machine.

![image](https://github.com/user-attachments/assets/d33180cf-6bf8-4939-a993-558ab47c1dcf)

*Device:* `acolyte756`

### Flag 1 – Initial PowerShell Execution Detection

**Objective:** Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.

With the system being indentified, finding the earliest suspicious powershell execution on the system was done by inspecting the 'DeviceProcessEvents' table. A KQL query was constructed filtering for any logs where the 'FileName' field contains the term "powershell" in it. 

This particluar log was noteworthy because the command forces a specific PowerShell version while running it silently and without logo or profile loading.

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2025-05-24)
| where DeviceName == "acolyte756"
| where FileName contains "powershell"
| project Timestamp,FileName,ProcessCommandLine
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/38cb1de7-d47a-4913-a662-b8b373ad9384)

*First Suspicious PowerShell Execution:* `2025-05-25T09:14:02.3908261Z`

### Flag 2 – Suspicious Outbound Signal

**Objective:** Confirm an unusual outbound communication attempt from a potentially compromised host.

To validate execution, I examined the initiating process and found the command line and path traced back to explorer.exe.
This strongly indicated that Bubba himself manually executed the malware.

```kql
DeviceNetworkEvents
| where DeviceName == "acolyte756"
| where isnotempty(RemoteUrl) 
| where RemoteIPType == "Public"
| where InitiatingProcessFileName has_any ("powershell.exe", "cmd.exe")
| project Timestamp, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/ac864d01-2698-43db-ac02-7ef5611479b0)

*Command-and-Control (C2) Server:* `eoqsu1hq6e9ulga.m.pipedream.net`

### Keylogger Artifact:
Following execution, a suspicious file named systemreport.lnk appeared in the AppData folder.
Its creation shortly after malware execution suggested keylogging or surveillance functionality—particularly because this was the only occurrence of that file on the system, and its timing implied intentional deployment for data collection.

```kql
DeviceFileEvents
| where DeviceName contains "anthony-001"
| where InitiatingProcessRemoteSessionDeviceName contains "bubba"
| where Timestamp >= datetime("2025-05-07T02:00:36.794406Z")
```
![image](https://github.com/user-attachments/assets/7b3740ff-14cf-457b-a440-56bb2fb7bb0d)

📌 *Artifact:* `systemreport.lnk`

### Registry Persistence:
Continuing, I reviewed registry modifications. A persistence key was identified in: HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
This entry was configured to launch BitSecSvc (an alias of the malware) on boot, establishing persistence across reboots.
```kql
DeviceRegistryEvents
| where RegistryKey contains "Run"
| where RegistryValueData has "BitSentinelCore"
```
![image](https://github.com/user-attachments/assets/3a05e25f-e17e-4d55-9082-b603d88490ce)

📌 *Key:* `HKCU\...\Run`

### Scheduled Task Creation:
Additional persistence was confirmed through scheduled task creation. 
The most notable task was titled UpdateHealthTelemetry, a deceptively benign name likely designed to blend in with legitimate Windows health-related processes.
This ensured long-term malware execution during system uptime.
```kql
DeviceProcessEvents
| where DeviceName contains "anthony"
| where ProcessCommandLine has "BitSentinelCore"
```
![image](https://github.com/user-attachments/assets/fcbbbd34-6a90-4b43-82ee-a0b8d0c652cc)

📌 *Task Name:* `UpdateHealthTelemetry`

### Process Chain:
Pulling together the execution chain, we confirmed the sequence:
```text
BitSentinelCore.exe -> cmd.exe -> schtasks.exe
```

---

## Summary of Findings

| Flag | MITRE Technique                    | Description                                                             |
| ---- | ---------------------------------- | ----------------------------------------------------------------------- |
| 1    | PowerShell                         | Initial use of PowerShell for script execution.                         |
| 2    | Application Layer Protocol         | Beaconing via HTTPS to external infrastructure (`pipedream.net`).       |
| 3    | Registry Run Keys/Startup Folder   | Persistence via `HKCU\...\Run` registry key with `C2.ps1`.              |
| 4    | Scheduled Task/Job                 | Alternate persistence through scheduled task `SimC2Task`.               |
| 5    | Obfuscated Files or Information    | Execution of base64-encoded PowerShell command.                         |
| 6    | Indicator Removal on Host          | PowerShell v2 downgrade to bypass AMSI/logging.                         |
| 7    | Remote Services: Scheduled Task    | Lateral movement using `schtasks.exe` targeting `victor-disa-vm`.       |
| 8    | Lateral Tool Transfer              | Use of `.lnk` files like `savepoint_sync.lnk` to stage/pivot.           |
| 8.1  | Registry Modification              | `savepoint_sync.ps1` registered for autorun.                            |
| 9    | Application Layer Protocol         | New beaconing to `eo1v1texxlrdq3v.m.pipedream.net`.                     |
| 10   | WMI Event Subscription             | Stealth persistence via WMI script `beacon_sync_job_flag2.ps1`.         |
| 11   | Credential Dumping Simulation      | Mimic of credential access via `mimidump_sim.txt`.                      |
| 12   | Data Staged: Local                 | Powershell process connects to `drive.google.com`.                      |
| 13   | Data from Information Repositories | Access of sensitive doc `RolloutPlan_v8_477.docx`.                      |
| 14   | Archive Collected Data             | Use of `Compress-Archive` to prepare ZIP payload.                       |
| 15   | Ingress Tool Transfer              | Staging of `spicycore_loader_flag8.zip`.                                |
| 16   | Scheduled Task/Job                 | Final scheduled task `SpicyPayloadSync` set to trigger script on logon. |

---

## Response Actions

* **Immediate Block:** Hashes and process signatures of `BitSentinelCore.exe` added to threat blocklists
* **Persistence Removal:** Startup `.lnk` file, registry key, and scheduled task manually removed
* **Telemetry Expansion:** Queries extended to check lateral movement beyond `anthony-001`
* **Awareness:** Flag shared with Blue Team and Detection Engineering for rule creation

---

## Lessons Learned

* Malware impersonating legitimate tools can easily evade static detection without behavioral telemetry.
* Scheduled tasks with realistic system names (`UpdateHealthTelemetry`) can persist undetected.
* LOLBins like `csc.exe` can be abused to compile and deploy malware post-download.
* Registry and Startup folders remain prime persistence targets.

---

**Report Completed By:** Aaron Martinez
**Status:**  flags investigated and confirmed
