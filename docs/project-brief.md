# Project 21 — Microsoft Sentinel SIEM Deployment & SOC Alert Triage
**NexaCore Technologies | SOC Division**  
**Assigned To:** Richmond A. Nkrumah — SOC Analyst Intern, Tier 2  
**Supervised By:** Daniel Osei-Mensah — Head of Cloud Infrastructure & Security  
**SOC Lead:** Abena Osei-Bonsu — Senior SOC Analyst 

---

## Background
NexaCore Technologies provisioned a Microsoft Azure subscription hosting an Azure App Service, Azure SQL Database, and Azure Active Directory (Entra ID) as the identity provider for 35 employees. Within two weeks of going live, suspicious sign-in activity was detected in Azure AD logs — multiple failed authentication attempts from unknown IP addresses targeting executive accounts.

NexaCore had no SIEM deployed for its Azure environment. This project involved deploying Microsoft Sentinel as the cloud-native SIEM, connecting data sources, writing KQL detection queries, enabling analytics rules, and building a SOC alert triage workflow.

---

## Infrastructure
| Resource | Details |
|---|---|
| Azure Subscription | Azure subscription 1 |
| Resource Group | cyberlab-rg — UK South |
| Log Analytics Workspace | cyberlab-law |
| Microsoft Sentinel | Free trial — 10GB/day |
| Data Connector | Microsoft Entra ID (Audit Logs, Non-Interactive Sign-In Logs) |

---

## What Was Built

### 1. Sandbox Setup
- Created resource group `cyberlab-rg` in UK South
- Deployed Log Analytics Workspace `cyberlab-law`
- Enabled Microsoft Sentinel with 31-day free trial

### 2. Data Connector
- Installed Microsoft Entra ID solution from Content Hub (73 analytics rules, 1 data connector, 3 workbooks)
- Connected Audit Logs and Non-Interactive User Sign-In Logs
- Confirmed log ingestion: AADNonInteractiveUserSignInLogs flowing within 15 minutes

### 3. KQL Detection Queries
Two production-grade KQL queries written and saved in `/queries`:

**Query 1 — Failed Sign-ins by IP Address**  
Detects brute force attempts by grouping failed authentication events by IP and user account over a 7-day window.

**Query 2 — Impossible Travel Detection**  
Detects users authenticating from two geographically different locations within 60 minutes using session serialization and prev() functions.

### 4. Analytics Rules Enabled
| Rule | Severity | MITRE Technique |
|---|---|---|
| Brute force attack against Azure Portal | Medium | T1110 — Credential Access |
| Anomalous sign-in location by user account | Medium | T1078 — Initial Access |

### 5. Log Generation & Audit Trail
Created and deleted a test user (`testsocuser`) to generate real Audit Log entries demonstrating the full SOC investigation workflow against live data.

---

## Key Findings
- Connector status confirmed Connected with logs flowing into `cyberlab-law`
- Sign-In Logs require Entra ID P1/P2 license — documented as a constraint; Audit Logs and Non-Interactive Sign-In Logs used as alternatives on free tier
- 2 analytics rules active and scheduled to run daily against incoming log data

---

## Tools & Technologies
Microsoft Sentinel · Azure Log Analytics · KQL · Microsoft Entra ID · Azure Content Hub · Microsoft Defender Portal · Azure Resource Manager

---

## Outcome
Microsoft Sentinel deployed and operational on `cyberlab-law`. Two KQL detection queries written and validated against real log data. Two analytics rules active covering brute force and anomalous sign-in scenarios. Full audit trail generated and queried demonstrating SOC investigation capability.