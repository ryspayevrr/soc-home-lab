# soc-home-lab
Home SOC lab built with Wazuh SIEM, Docker, and Sysmon for Windows threat detection, MITRE ATT&amp;CK simulation, and incident response.

# Home SOC Lab: Wazuh SIEM & Windows Threat Detection

## 1. Overview
This project demonstrates an end-to-end local Security Operations Center (SOC) lab built to practice log ingestion, telemetry enrichment, attack simulation, detection engineering, and incident response.

The environment consists of a containerized Wazuh SIEM server monitoring an isolated Windows 10 endpoint enhanced with Sysmon, simulating real-world techniques mapped to the **MITRE ATT&CK** framework.

---

## 2. Architecture & Tech Stack

### Network & Infrastructure Diagram



### Tech Stack
* **Host OS (Attacking Machine) & Hypervisor:** Arch Linux, QEMU/KVM ('libvirt' / 'virt-manager')
* **Containerization:** Docker & Docker Compose (Single-node Wazuh deployment)
* **SIEM / XDR:** Wazuh v4.14 (Manager, Indexer, Dashboard)
* **Monitored Endpoint:** Windows 10 Pro (VirtIO drivers, 2 vCPU, 4 GB RAM)
* **Endpoint Telemetry:** Microsoft Sysmon (configured with 'sysmon-config'), Windows Security Event Logs, PowerShell Operational Logs
* **Attack Simulation Tools:** Nmap, THC-Hydra, native Windows LOLBins (PowerShell, 'reg.exe')

---

## 3. Lab Deployment & Telemetry Setup
*in process*

---

## 4. Detection Engineering (Custom Rules)
*in process*

---

## 5. Attack Scenarios & Incident Reports

* **Scenario 1:** Network Reconnaisance & Brute Force ('T1046', 'T1110')
* **Scenario 2:** Obfuscated PowerShell Execution & Registry Persistence ('T1059.001', 'T1547.001')
