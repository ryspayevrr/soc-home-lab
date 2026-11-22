# soc-home-lab
Home SOC lab built with Wazuh SIEM, Docker, and Sysmon for Windows threat detection, MITRE ATT&amp;CK simulation, and incident response.

# Home SOC Lab: Wazuh SIEM & Windows Threat Detection

## 1. Overview
This project demonstrates an end-to-end local Security Operations Center (SOC) lab built to practice log ingestion, telemetry enrichment, attack simulation, detection engineering, and incident response.

The environment consists of a containerized Wazuh SIEM server monitoring an isolated Windows 10 endpoint enhanced with Sysmon, simulating real-world techniques mapped to the **MITRE ATT&CK** framework.

---

## 2. Architecture & Tech Stack

### Infrastructure Topology
* **Network Bridge:** Isolated NAT virtual network ('virbr0' - '192.168.122.0/24')
* **SIEM Server (Host):** '192.168.122.1' (ports '1514\tcp' for agent log ingestion, '1515\tcp' for enrollment, '443\tcp' for Wazuh Dashboard
* **Monitored Endpoint (VM):** 'Win10-Target' ('192.168.122.x')

  *pic*


### Tech Stack
* **Host OS (Attacking Machine) & Hypervisor:** Arch Linux, QEMU/KVM ('libvirt' / 'virt-manager')
* **Containerization:** Docker & Docker Compose (Single-node Wazuh deployment)
* **SIEM / XDR:** Wazuh v4.14.10 (Manager, Indexer, Dashboard)
* **Monitored Endpoint:** Windows 10 Pro (VirtIO storage & drivers, 2 vCPU, 4 GB RAM)
* **Endpoint Telemetry:** Microsoft Sysmon v15.22 (configured with 'sysmon-config'), Windows Security Event Logs
* **Attack Simulation Tools:** Nmap, THC-Hydra, native Windows LOLBins ('powershell.exe', 'certutil.exe', 'reg.exe')

---

## 3. Lab Deployment & Telemetry Setup

### 3.1 Wazuh SIEM Deployment (Docker)
The Wazuh single-node stack was deployed via Docker Compose with self-signed TLS cert-s generated with 'generate-indexer-certs.yml':
* 'wazuh.manager' - log parsing, decoding, and rule evaluation engine
* 'wazuh.indexer' - log storage and indexing
* 'wazuh.dashboard' - web UI for alert triage and visualization

### 3.2 Endpoint Telemetry Enrichment (Sysmon)
To overcome the visibility gaps of default Windows logs (full command-line args, parent-child process trees, and network connections per process), MS Sysmon was installed on 'Win10-Target' using a community config baseline:

```
powershell
Sysmon64.exe -accepteula -i sysmonconfig.xml
```

### 3.3 Wazuh Agent Configuration
The Wazuh Agent was registered with the manager at 192.168.122.1 and configured to ingest the Sysmon operational event channel by appending the following XML block to 'C:\Program Files (x86)\ossec-agent\ossec.conf':
```
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
#### Verification

<img width="3058" height="1118" alt="image" src="https://github.com/user-attachments/assets/5a3f2f4f-9458-4f0a-857e-bb03ccdcb145" />


---

## 4. Detection Engineering (Custom Rules)
*in process*

---

## 5. Attack Scenarios & Incident Reports

| # | Scenario | MITRE ATT&CK Technique | Detection Source | Status |
| :--- | :--- | :--- | :--- | :--- |
| 1 | Network Reconnaissance & RDP/SMB Brute Force | `T1046`, `T1110` | Windows Security Log (`4625`) | Planned |
| 2 | Obfuscated PowerShell & LOLBin Execution | `T1059.001`, `T1105` | Sysmon (`Event ID 1`, `Event ID 3`) | Planned |
| 3 | Registry Run Key Persistence | `T1547.001` | Sysmon (`Event ID 13`) | Planned |
