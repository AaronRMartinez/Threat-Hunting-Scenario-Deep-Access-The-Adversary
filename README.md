# Threat-Hunting-Scenario-Deep-Access-The-Adversary

![image](https://github.com/user-attachments/assets/f42ca88e-ef22-4b6f-9748-bbf6fe97367e)

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

This particluar log was noteworthy because the command `"powershell.exe" -Version 5.1 -s -NoLogo -NoProfile` forces a specific PowerShell version while running it silently and without logo or profile loading.

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

In order to identify any suspicious outbound communication from the suspected system, the 'DeviceNetworkTable' was inspected. A KQL query was created that specifically searched for events initiated by either PowerShell or CommandPrompt with an associated public `RemoteIPType', denoting an outbound connection.

Using this query, I was able to filter for any relevant log with the designated parameters and identified both a relevant log and URL. An outbound connection communicating to the URL `eoqsu1hq6e9ulga.m.pipedream.net` was logged with  both the same initiating filename and the same initiating process command line (`"powershell.exe" -Version 5.1 -s -NoLogo -NoProfile`) as the previous flag.

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

### Flag 3 – Registry-based Autorun Setup

**Objective:** Detect whether the adversary used registry-based mechanisms to gain persistence.

Being aware that the threat attacker employed registry-based mechanisms for persistence, the logical table to inspect is the `DeviceRegistryTable` which focuses on registry events. An important detail that was provided to us, was that the registry mechanism is utilizing an `AutoRun` method. An `AutoRun` is a method that allows programs, scripts, or processes to automatically start without user action — typically when the system boots, or when a user logs in. In general, `AutoRuns` are located in a specific location within the registry, that being: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`. The important detail of the registry location is that the `AutoRun` mechanisms reside in the `Run` directory. A KQL query that specified this location in the registry would filter a lot of irrelevant logs.

```kql
DeviceRegistryEvents
| where DeviceName == "acolyte756"
| where RegistryKey contains "run"
| order by Timestamp asc
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
```

![image](https://github.com/user-attachments/assets/12ddee5c-9454-4ec8-b7f3-67d9fe697280)

*Malicious AutoRun:* `C2.ps1`

### Flag 4 – Scheduled Task Persistence

**Objective:** Investigate the presence of alternate autorun methods used by the intruder.

A "Scheduled Task" is a Windows mechanism that allows programs, commands, or scripts to run automatically at startup, on user logon, at scheduled times, or in response to specific system events. "Scheduled Tasks" are generally stored in the `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks` registry. To focus my search for any relevant malicious scheduled tasks in the `DeviceRegistryEvents` table, I queried for logs residing within the "Schedule" location in the registry.

```kql
DeviceRegistryEvents
| where DeviceName == "acolyte756"
| where RegistryKey contains "Schedule"
| project Timestamp, RegistryKey, RegistryValueData, InitiatingProcessFileName
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/9eab2b57-69be-47b0-a621-ef9ee0ea16b9)

*Registry Value of the Malicious Scheduled Task:* `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SimC2Task`

### Flag 5 – Obfuscated PowerShell Execution

**Objective:** Uncover signs of script concealment or encoding in command-line activity.

Obfuscated PowerShell commands are a common techniques malicious actors employ to conceal their activtiy within a system. These powershell commands typically contain an a flag denoting that the command is obfuscated. The PowerShell flag is usually either `-EncodedCommand` or some shorthand iteration of it, such as `-enc` or `-e`. A KQL query specifically inspecting "PowerShell" logs containing either of the previously mentioned flags would focus the search to relevant logs.

```kql
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where FileName contains "powershell"
| where ProcessCommandLine has_any("-EncodedCommand", "-enc", "-e") 
| order by Timestamp asc 
| project Timestamp, ProcessCommandLine, InitiatingProcessCommandLine
```

![image](https://github.com/user-attachments/assets/68bfcf46-b455-41c4-ad8c-0bf7f03c099a)

*The Obfuscated Command:* `"powershell.exe" -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAaQBtAHUAbABhAHQAZQBkACAAbwBiAGYAdQBzAGMAYQB0AGUAZAAgAGUAeABlAGMAdQB0AGkAbwBuACIA`

### Flag 6 – Evasion via Legacy Scripting

**Objective:** Detect usage of outdated script configurations likely intended to bypass modern controls.

A downgrade attack is a type of cyberattack where an attacker forces a system to use weaker security protocols or outdated, less secure versions of software or hardware. A typical downgrade attack command explicitly refers to a software or hardware's version it wants to utilize. Understanding that the malicious actor had been utilizing PowerShell to carry out it's activtiy in the system, I searched for logs with the `FileName` field and the term "version". The word "version" because it could be within a PowerShell command attempting to utilizing outdated software.

```kql
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where FileName contains "powershell"
| where ProcessCommandLine contains "version"
| project Timestamp,ProcessCommandLine
| order by Timestamp asc
```

![image](https://github.com/user-attachments/assets/93d2e8c7-7024-44ee-9268-8987360975ea)

*The Downgrade Attack Command:* `"powershell.exe" -Version 2 -NoProfile -ExecutionPolicy Bypass -NoExit`

### Flag 7 – Remote Movement Discovery

**Objective:** Reveal the intruder's next target beyond the initial breach point.

Having previously noticed that MDE created an incident involving the suspected `acolyte756`, it flagged the device with the `Lateral Movement` tag. Which denotes that an attacker has moved laterally between endpoint systems. 

![image](https://github.com/user-attachments/assets/de8621e2-328e-4122-acfb-3b3ca0886523)

Opening the incident report generated by MDE, I searched and focused on the "lateral movement" element of the incident. Under the "Evidence" section, the process ID of an associated PowerShell process used in the attack was logged. The PID of the malicious PowerShell process was `6944`.

![image](https://github.com/user-attachments/assets/8213cf44-e140-4dd1-94e4-38c90a72da20)

With this PID, I crafted a KQL query to filter for logs within the `DeviceProcessEvents` table to have an initiating process ID of `6944`. The query not only returned previously discovered logs and flags, but also  returned process activity relevant to the current threat hunting. One of the returned log pertains to the creation of a remote scheduled task. The command, `"schtasks.exe" /Create /S victor-disa-vm /U victor-disa-vm\adminuser /P ********** /TN RemoteC2Task /TR "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\C2.ps1" /SC ONLOGON` creates a scheduled task `(/S victor-disa-vm)` on a remote system `victor-disa-vm`.

```kql
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where InitiatingProcessId == "6944"
| project Timestamp,FileName,ProcessCommandLine
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/643c792d-90fb-4c8f-a637-1f6fc8207901)

*Attacker's Next Target:* `victor-disa-vm`

### Flag 8 – Entry Indicators on Second Host

**Objective:** Identify the subtle digital footprints left during a pivot.

This flag was really tricky for me as I initially unclear what I was looking forward. Referring to what I should be searching for on the second system the attacker pivoted to, the terms "point", "sync", and "stage" were distinct to me. Looking for these terms within a process command line, I constructed a KQL query to inspect the `DeviceProcessEvents` table in the `victor-disa-vm` system. The first log entry returned the file name of the relevant flag.

```kql
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where ProcessCommandLine has_any ("stage", "point", "sync")
| project Timestamp,FileName,ProcessCommandLine
| order by Timestamp asc
```

![image](https://github.com/user-attachments/assets/775b61c1-0b2b-4740-ae90-71ec5ea327fc)

*Suspicious File Name on Second Host :* `savepoint_sync.lnk`

### Flag 8.1 – Persistence Registration on Entry

**Objective:** Detect attempts to embed control mechanisms within system configuration.

From previously observed techniques employed by the attacker to gain persistence on target systems, the malicious threat actor utilizes PowerShell to establish persistent mechanisms with either a "Schedule Task" or an "AutoRun". The respective registry keys were then inspected in the `DeviceRegistryEvents` table to see if any new registry values were either created or set. The first log returned from the query provided the flag.

```kql
DeviceRegistryEvents
| where DeviceName == "victor-disa-vm"
| where RegistryKey has_any("run", "schedule")
| where ActionType == "RegistryValueSet" or ActionType == "RegistryKeyCreated"
| project Timestamp, ActionType, RegistryKey, RegistryValueData
| order by Timestamp asc
```

![image](https://github.com/user-attachments/assets/159787e5-158d-47d6-9ed5-7c7259ff286d)

*Registry Value Data:* `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\savepoint_sync.ps1"`

### Flag 9 – External Communication Re-established

**Objective:** Verify if outbound signals continued from the newly touched system.

Having observed the threat actor use the same technique to establish persistence on the second system as they did with the first one, one would assume that the attacker would utilize the same C2 server as before. Narrowing the KQL query to the second system and referencing the previously discovered C2 domain name, several logs were returned that supported the assumption of the attacker establishing an outbound connection with the same C2 server.

```kql
DeviceNetworkEvents
| where DeviceName contains "victor-disa-vm"
| where RemoteUrl contains "pipedream.net"
| order by Timestamp asc
| project Timestamp, ActionType, RemoteUrl, InitiatingProcessCommandLine
```

![image](https://github.com/user-attachments/assets/3ea3923d-06b9-4207-9de5-d1030eadfe58)

*Command-and-Control (C2) Server:* `eoqsu1hq6e9ulga.m.pipedream.net`

### Flag 10 – Stealth Mechanism Registration

**Objective:** Uncover non-traditional persistence mechanisms leveraging system instrumentation.

Throught the attack, the threat actor has utilized PowerShell scripts to establish persistence on both targeted systems. Filtering logs that involve PowerShell scripts would narrow the search. Along with it, there is explicit mention of Windows Management Instrumentation (WMI) and the term "beacon" being associated with the file name of the associated malicious file. With these specific details, a KQL query incorporating this information was created. 

```kql
DeviceProcessEvents
| where DeviceName contains "victor-disa-vm"
| where ProcessCommandLine contains ".ps1" and ProcessCommandLine contains "beacon"
| where * contains "WMI"
| order by Timestamp asc
| project Timestamp, FileName, ActionType, ProcessCommandLine
```

![image](https://github.com/user-attachments/assets/7544194b-7b29-4e96-8af3-d00a7099ae50)

*Timestamp :* `2025-05-26T02:48:07.2900744Z`

### Flag 11 – Suspicious Data Access Simulation

**Objective:** Detect test-like access patterns mimicking sensitive credential theft.

As alluded before, the attacker has extensively used PowerShell in the compromised systems to conduct their activity. Focusing on logs where the `FileName` field contains the term "powershell" would filter out much of the noise within the `DeviceProcessEvents` table. It is provided that possible credential dumping could be occurring with a mimikatz variant. Mimikatz is a powerful open-source tool that allows users to extract sensitive information, such as passwords and credentials, from a system's memory. A KQL query focusing on process command lines containing the term "mimi", searching for possible Mimikatz variants, or the term "dump", which is a common command used in credential dumping, would return relevant logs.

```kql
DeviceProcessEvents
| where DeviceName contains "victor-disa-vm"
| where FileName contains "powershell"
| where ProcessCommandLine contains "mimi" or ProcessCommandLine contains "dump"
| order by Timestamp asc
| project Timestamp, FileName, ProcessCommandLine
```

![image](https://github.com/user-attachments/assets/4baaf30a-43f6-4000-90d7-5cda953ab43f)

*File:* `mimidump_sim.txt`

### Flag 12 – Unusual Outbound Transfer

**Objective:** Investigate signs of potential data transfer to untrusted locations.

Using the process event log that contained the previous flag, a SHA256 hash can be extracted from the process initiating the action. Extracting the SHA256 hash value `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`, the hash was used in another query within the `DeviceNetworkEvents` table to filter for relevant network logs. Using the extracted hash value to seek network events initiated by the same process SHA256 value returned network traffic to the same primary domain of the attacker's C2 server.

```kql
DeviceProcessEvents
| where DeviceName contains "victor-disa-vm"
| where FileName contains "powershell"
| where ProcessCommandLine contains "mimi" or ProcessCommandLine contains "dump"
| order by Timestamp asc
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessSHA256
```

![image](https://github.com/user-attachments/assets/da09aac2-7e07-4309-91de-6c60d4e8ee3b)

```kql
DeviceNetworkEvents
| where DeviceName contains "victor-disa-vm"
| where InitiatingProcessSHA256 == "9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3"
| where RemoteIPType == "Public"
| order by Timestamp asc
| project Timestamp, RemoteUrl ,InitiatingProcessFileName, InitiatingProcessCommandLine
```

![image](https://github.com/user-attachments/assets/c77c965f-6ae4-407b-b5b2-9923870c30f4)

*SHA256:* `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`

### Flag 13 – Sensitive Asset Interaction

**Objective:** Reveal whether any internal document of significance was involved.

Any relevant, logged file activtiy would be found querying the `DeviceFileEvents` table. The provided hint mentions that the organization believes the threat actor may have targeted a document associated with current year's end month projects. Specifically detailing that the format of yyyy-mm would be associated with the targeted document. 

```kql
DeviceFileEvents
| where DeviceName == "victor-disa-vm"
| where FolderPath contains "2025-05"
| order by Timestamp asc
| project Timestamp, FolderPath, InitiatingProcessCommandLine
```

![image](https://github.com/user-attachments/assets/afc922b0-6935-4f04-a7db-aa3f2037115e)

*Targeted File:* `RolloutPlan_v8_477.docx`

### Flag 14 – Tool Packaging Activity

**Objective:** Spot behaviors related to preparing code or scripts for movement.

Being aware that the threat actor was possibly compressing files in order to prepare them for movement, I focused on both common and native compression techniques. Such as either compressing the files into a "zip" file or utilizing the "7z.exe" program to compress the files. I searched the `DeviceProcessEvents` table for logs containing process command lines involving ".zip" files or the "7z.exe" program. Looking through the returned process logs, a PowerShell initiated event involving the compression of files was discovered.

```kql
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where ProcessCommandLine contains ".zip" or ProcessCommandLine contains "7z.exe"
| order by Timestamp asc
| project Timestamp, FileName, ProcessCommandLine
```

![image](https://github.com/user-attachments/assets/ae83be6f-da8d-484f-bd96-c8c67f8592dd)

*Command:* `"powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command Compress-Archive -Path "C:\Users\Public\dropzone_spicy" -DestinationPath "C:\Users\Public\spicycore_loader_flag8.zip" -Force`

### Flag 15 – Deployment Artifact Planted

**Objective:** Verify whether staged payloads were saved to disk.

This flag was pretty straight forward after the discovery of the threat actor's command in the previous exercise. The attacker's command explicitly refers to not only the destination of where the file is being copied to, but includes the name of the new file being created on the system. `-DestinationPath "C:\Users\Public\spicycore_loader_flag8.zip"`. Constructing a KQL query searching the `victor-disa-vm` system for the mentioned file name `spicycore_loader_flag8.zip`, verified that the file had been created on the system.

```kql
DeviceFileEvents
| where DeviceName == "victor-disa-vm"
| where FileName contains "spicycore_loader_flag8.zip"
| order by Timestamp asc
```

![image](https://github.com/user-attachments/assets/f1408665-916e-452b-94f6-4fe23ec9ad6c)

*Malicious Tool:* `spicycore_loader_flag8.zip`

### Flag 16 – Persistence Trigger Finalized

**Objective:** Identify automation set to invoke recently dropped content.

The attacker wanting to gain persistence on the target system, created a schedule task to establish persistence. The threat actor had been exclusively utilizing PowerShell as the initiaiting file for their persistence techniques so sfiltering for this element would focus my search. To narrow down my query for relevant event logs, I focused on the `DeviceProcessEvents` table with process command lines containing references to schedule task activity (schtasks). 

```kql
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where ProcessCommandLine contains "schtasks"
| order by Timestamp desc
| project Timestamp, InitiatingProcessFileName, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/d30add62-a6af-4d02-bed3-9acb77c86ff9)

*Timestamp of Schedule Task Creation Attempt:* `2025-05-26T07:01:01.6652736Z`

---

## Summary of Findings

| Flag # | Flag                             | Description                                                             |
| ---- | ---------------------------------- | ----------------------------------------------------------------------- |
| 1    | 2025-05-25T09:14:02.3908261Z                         | Time of first observed activity by the threat actor                       |
| 2    | eoqsu1hq6e9ulga.m.pipedream.net         | External command-and-control (C2) server used for remote communication      |
| 3    | C2.ps1   | PowerShell script leveraged within the registry for persistence              |
| 4    | HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SimC2Task                 | Registry data value of an alternate persistence mechanism configured by the threat actor               |
| 5    | "powershell.exe" -EncodedCommand VwB...ACIA    | PowerShell obfuscated command                              |
| 6    | "powershell.exe" -Version 2 -NoProfile -ExecutionPolicy Bypass -NoExit          | Downgrade attack commandline                         |
| 7    | victor-disa-vm    | Target system during lateral movement by the attacker       |
| 8    | savepoint_sync.lnk             | Attacker tools moved during lateral movement           |
| 8.1  | powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\savepoint_sync.ps1"              | Registry data value of a configured AutoRun used for persistence                            |
| 9    | eo1v1texxlrdq3v.m.pipedream.net         | C2 server used for remote communication on second targeted system                     |
| 10   | 2025-05-26T02:48:07.2900744Z             | Earliest timestamp of the attacker's activtiy attempting to gain persistence with a PowerShell script via WMI        |
| 11   | mimidump_sim.txt      | Mimikatz variant used by the attacker to conduct credential harvesting                      |
| 12   | 9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3                 | SHA256 value of the process conducting data exfiltration                      |
| 13   | RolloutPlan_v8_477.docx | Sensitive document targeted by the attacker                      |
| 14   | "powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command Compress-Archive -Path "C:\Users\Public\dropzone_spicy" -DestinationPath "C:\Users\Public\spicycore_loader_flag8.zip" -Force             | Command line used to compress a malicious tool used by the attacker                     |
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

