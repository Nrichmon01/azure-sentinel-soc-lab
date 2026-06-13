# SOC Triage Runbook — Microsoft Sentinel Lab

**Project:** Azure Sentinel SOC Lab (cyberlab-rg · UK South)  
**Workspace:** cyberlab-law  
**Last updated:** June 2026

## Overview

This runbook defines the triage and investigation workflow for two analytics rules deployed in this lab:

1. Brute force attack against Azure Portal (T1110)
2. Anomalous sign-in location by user account (T1078)

---

## Alert 1 — Brute force attack against Azure Portal

**Rule name:** Brute force attack against Azure Portal  
**MITRE ATT&CK:** T1110 — Brute Force  
**Severity:** Medium  
**Data source:** SigninLogs (Entra ID)  
**Trigger:** Multiple failed sign-in attempts from a single IP within a short window

### Step 1 — Acknowledge and assess

1. Open the incident in **Sentinel → Incidents**
2. Note the incident ID, affected entity (user or IP), and alert time
3. Set status to **Active** and assign to yourself
4. Check the incident timeline for number of failed attempts and timespan

### Step 2 — Investigate with KQL

Run this query in **Sentinel → Logs** to scope the activity:

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| summarize FailedAttempts = count(), Users = make_set(UserPrincipalName)
    by IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| order by FailedAttempts desc
```

Key questions to answer:
- How many failed attempts from the flagged IP?
- Are multiple accounts targeted (password spray) or one account (credential stuffing)?
- Did any attempt succeed (ResultType = 0)?

### Step 3 — Enrich the IP

1. Copy the source IP from the query results
2. Look it up on [AbuseIPDB](https://www.abuseipdb.com) or [VirusTotal](https://www.virustotal.com)
3. Check geolocation — is it expected for this user?
4. Check if the IP appears on any known threat feed

### Step 4 — Check for successful sign-in

```kql
SigninLogs
| where IPAddress == "<flagged_ip>"
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
```

> If a successful sign-in exists after the failed attempts, escalate immediately — treat as potential account compromise.

### Step 5 — Contain

| Condition | Action |
|---|---|
| No successful sign-in | Monitor and document, close as Benign Positive |
| Successful sign-in detected | Disable account, revoke sessions, escalate |
| IP is known malicious | Block via Conditional Access policy |

To disable a user in Entra ID:
- Navigate to **Entra ID → Users → [User] → Edit → Account enabled → Off**

### Step 6 — Document and close

1. Add investigation notes to the incident
2. Tag with `T1110`, severity, and outcome
3. Set classification: **True Positive**, **False Positive**, or **Benign Positive**
4. Close with a resolution summary

---

## Alert 2 — Anomalous sign-in location by user account

**Rule name:** Anomalous sign-in location by user account  
**MITRE ATT&CK:** T1078 — Valid Accounts  
**Severity:** Medium  
**Data source:** SigninLogs (Entra ID)  
**Trigger:** Same user signs in from two geographically distant locations within 60 minutes

### Step 1 — Acknowledge and assess

1. Open the incident in **Sentinel → Incidents**
2. Note the two sign-in locations and the time gap between them
3. Determine if travel between the two locations in that time is physically possible
4. Set status to **Active** and assign to yourself

### Step 2 — Investigate with KQL

```kql
let TimeDelta = 60m;
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, CountryOrRegion
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(24h)
    | where ResultType == "0"
    | project UserPrincipalName, TimeGenerated2 = TimeGenerated,
        IPAddress2 = IPAddress, Location2 = Location
) on UserPrincipalName
| where abs(datetime_diff('minute', TimeGenerated, TimeGenerated2)) < 60
    and Location != Location2
```

Key questions to answer:
- What are the two locations and time gap between sign-ins?
- Are both sign-ins successful?
- Is either IP associated with a VPN or Tor exit node?

### Step 3 — Enrich and qualify

1. Check the user's historical sign-in locations in **Entra ID → Sign-in logs**
2. Check if either IP resolves to a VPN provider — most common false positive cause
3. Contact the user if account compromise is suspected

### Step 4 — Determine the most likely scenario

| Scenario | Indicator | Action |
|---|---|---|
| VPN usage | IP belongs to known VPN provider | Document as Benign Positive |
| Legitimate travel | User confirms travel | Close as Benign Positive |
| Shared credentials | Both sign-ins active simultaneously | Disable account, escalate |
| Account takeover | User denies one sign-in | Disable account immediately, escalate |

### Step 5 — Contain (if account takeover suspected)

1. Disable the user account in Entra ID
2. Revoke all active sessions: **Entra ID → Users → [User] → Revoke sessions**
3. Reset credentials and force MFA re-registration
4. Review all activity from the suspicious session:

```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where InitiatedBy.user.userPrincipalName == "<compromised_user>"
| project TimeGenerated, OperationName, TargetResources, Result
```

### Step 6 — Document and close

1. Record the full timeline of both sign-in events
2. Note any user contact and their response
3. Set classification and close with resolution summary

---

## General escalation criteria

Escalate to a senior analyst or IR team if any of the following are true:

- A successful sign-in follows a brute force sequence
- An anomalous sign-in is confirmed by the user as unauthorised
- Lateral movement indicators appear in audit logs post-compromise
- A privileged account is targeted (Global Admin, Security Admin)

---

## Environment notes

| Item | Detail |
|---|---|
| Sentinel workspace | cyberlab-law · UK South |
| Free trial expires | July 14, 2026 |
| Log ingestion limit | 10 GB/day |
| Entra ID tier | Free — P1/P2 not available, sign-in log access limited |
| AuditLogs | Configured but slow to ingest on free tier |

---

*This runbook is part of the NexaCore Technologies cloud security internship portfolio — Project 21. Note: NexaCore Technologies is a fictional company name used for portfolio presentation purposes.*