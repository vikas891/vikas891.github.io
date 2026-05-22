---
title: "VPN Vulnerabilities and Forensic Log Analysis"
description: "Investigation guide covering VPN activity across major firewall vendors with SIEM focused queries and forensic analysis techniques."
date: 2025-02-14 20:30:00 +0530
categories: [Forensics]
tags: [dfir, siem]
---
## 1. Introduction

Based on extensive research into recent VPN exploitation campaigns, this article provides a structured guide for the forensic investigation of compromised firewall VPN systems. 

VPN devices have become primary access points for advanced threat actors, ransomware groups, and intrusion operators. Repeated exploitation of zero-day and n-day vulnerabilities highlights an important shift. Perimeter appliances are no longer just security controls. They are also forensic evidence sources that help identify intrusions early.

The sections that follow provide a vendor-specific playbook with:

- **Vulnerability and Exploitation Overview** covering notable CVEs and attacker behaviors.  
- **Forensic Analysis and Log Investigation** explaining where logs reside, how to parse them, and how to use Microsoft Sentinel (KQL) for hunting.
  
---
## 2. Fortinet FortiGate VPN

### 2.1 Vulnerability and Exploitation Overview

FortiGate SSL VPN appliances have been widely targeted in real-world attacks. Threat actors often rely on credential theft, session hijacking, or exploitation of unpatched vulnerabilities such as **CVE-2018-13379**, a path traversal flaw heavily abused by ransomware groups and APT actors.

Once authenticated, attackers establish SSL tunnels that blend seamlessly with legitimate traffic. This makes VPN log analysis an important early detection step.

### 2.2 Forensic Analysis and Log Investigation

#### How Customers Export VPN Logs

Fortinet allows administrators to export VPN logs directly from the web interface.

> This workflow applies to most customer deployments running SSL VPN.
{: .prompt-tip }

**Typical workflow:**

- Log into the FortiGate device and navigate to **Log and Report**.  
- Select **VPN Logs** or **Traffic Logs**, depending on configuration.  
- Use **Export** to download logs in CSV or other supported formats.

Reference: [Article](https://community.fortinet.com/t5/FortiAnalyzer/Technical-Tip-How-to-create-a-VPN-report-for-users-connection/ta-p/298648)

#### Raw Fortinet (FortiGate) VPN Logs

Fortinet syslog entries use structured key-value pairs. Common fields include:

- `user="bob.smith@example.com"`  
- `action="tunnel-up"`  
- `tunneltype="ssl-tunnel"`  
- `remip=203.0.113.55`

> These logs are easy to parse and normalize due to their structured format.
{: .prompt-info }

#### SIEM Based Investigation
> Use this query in Microsoft Sentinel to identify successful SSL VPN connections and extract key user metadata.
{: .prompt-info }

```terminal
CommonSecurityLog
//CommonSecurityLog for CSP customers.
| where DeviceVendor == "Fortinet"
| where DeviceProduct == "Fortigate"
// Identify successful SSL VPN logins via tunnel-up with ssl-tunnel tunneltype
| where DeviceAction == "tunnel-up"
      and AdditionalExtensions contains "FTNTFGTtunneltype=ssl-tunnel"
// Extract details from AdditionalExtensions
| extend User = coalesce(
    extract(@"FTNTFGTuser=""([^""]+)""", 1, AdditionalExtensions),
    extract(@"user=([^; ]+)", 1, AdditionalExtensions),
    "<unknown>"
  )
| extend LogID = extract(@"FTNTFGTlogid=([^;]+)", 1, AdditionalExtensions),
         TunnelType = "ssl-tunnel"
| project TimeGenerated, SourceIP, User, LogID, TunnelType, DeviceAction, AdditionalExtensions
| sort by TimeGenerated desc
```
{: file="KQL Query" }
This research is based off of [Technical Tip: SSL VPN event logs when successfully connected](https://community.fortinet.com/t5/FortiGate/Technical-Tip-SSL-VPN-event-logs-when-successfully-connected/ta-p/331206)

---
## 3. SonicWall SSL-VPN

### 3.1 Vulnerability & Exploitation Overview

SonicWall SSL-VPN devices have faced credential brute force, zero-day exploits, and session hijacking attempts. Threat actors may use harvested credentials for persistence.

### 3.2 Forensic Analysis & Log Investigation

#### How Customers Export VPN Logs

SonicWall (SonicOS Web UI)

- Navigate to **Monitor → Logs → System Logs** (or **Log → View** for some versions).
- You can filter or search logs on-screen first to reduce export size.
- Click **Export**, and choose the file format:
  - **CSV** – ideal for Excel or further processing.
  - **Plain Text** – for standard logging or alert emails.

#### SonicWall Log File Formats

- Exported logs might appear as CSV or plain text, depending on format choice.
- Fields typically include timestamps, activity types, IP addresses, and user details.
- For example, network tunnel audit logs (**netaudit.csv**) or system messages are clearly labeled.

#### SIEM Based Investigation
> Use this query in Microsoft Sentinel to identify successful SSL VPN connections and extract key user metadata.
{: .prompt-info }
```terminal
CommonSecurityLog
| where DeviceVendor == "SonicWall"
| where DeviceProduct == "NSA 2700"
| where Activity has "login" or Activity has "logon"
//| where Activity == "Successful SSL VPN User Login"
// Robust username extraction:
// 1. DeviceCustomString6 directly (remove quotes if present)
// 2. From AdditionalExtensions via susr="username"
| extend User = trim(@"""", tostring(DeviceCustomString6))
| extend User = iff(isempty(User),
                    extract(@"susr=""([^""]+)""", 1, AdditionalExtensions),
                    User)
| project 
    TimeGenerated,
    Activity,
    User,
    SourceIP,
    DestinationIP,
    DeviceVendor,
    DeviceProduct,
    DeviceVersion,
    Computer
| sort by TimeGenerated asc 
```
{: file="KQL Query" }
```terminal
CommonSecurityLog
| where DeviceVendor == "SonicWall"
| where DeviceProduct == "NSA 2700"
| where Activity has "login" or Activity has "logon"
//| where Activity == "Successful SSL VPN User Login"
// Robust username extraction:
// 1. DeviceCustomString6 directly (remove quotes if present)
// 2. From AdditionalExtensions via susr="username"
| extend User = trim(@"""", tostring(DeviceCustomString6))
| extend User = iff(isempty(User),
                    extract(@"susr=""([^""]+)""", 1, AdditionalExtensions),
                    User)
// Enrich with geolocation details for the source IP
| extend Geo = geo_info_from_ip_address(SourceIP)
| extend Country   = tostring(parse_json(Geo).country),
         State     = tostring(parse_json(Geo).state),
         City      = tostring(parse_json(Geo).city),
         Latitude  = tostring(parse_json(Geo).latitude),
         Longitude = tostring(parse_json(Geo).longitude)
| project 
    TimeGenerated,
    Activity,
    User,
    SourceIP,
    Country,
    State,
    City,
    Latitude,
    Longitude,
    DestinationIP,
    DeviceVendor,
    DeviceProduct,
    DeviceVersion,
    Computer
| sort by TimeGenerated asc 
```
{: file="With Geolocation" }

>Sample Log Output
{: .prompt-info }

| Time Generated (UTC)         | Activity                          | User                  | SourceIP         | Country           | State          | City          |
| ---------------------------- | --------------------------------- | --------------------- | ---------------- | ----------------- | -------------- | ------------- |
| 6/15/2025 11:15:08.191 AM    | Successful SSL VPN User Login     | user_1@acme.corp      | 167.196.11.118   | United States     | Illinois       | West Bend     |
| 6/15/2025 11:11:47.053 AM    | Successful SSL VPN User Login     | user_2@acme.corp      | 98.97.4.74       | United States     | Wisconsin      | West Bend     |
| 6/15/2025 7:35:25.770 AM     | Successful SSL VPN User Login     | user_9@acme.corp      | 76.217.178.158   | United States     | California     | Encinitas     |
| **6/15/2025 4:11:38.776 AM** | **Successful SSL VPN User Login** | **evilguy@acme.corp** | **64.20.57.227** | **United States** | **California** | **Escondido** |
| 6/15/2025 4:09:44.899 AM     | Successful SSL VPN User Login     | user_11@acme.corp     | 167.196.11.118   | United States     | Wisconsin      | West Bend     |
| 6/15/2025 3:06:42.868 AM     | Successful SSL VPN User Login     | user_12@acme.corp     | 148.245.54.12    | Canada            | Quebec         | Montreal      |
| 6/15/2025 5:07:14.956 PM     | Unknown User Login Attempt        | user_13@acme.corp     | 88.210.63.62     | Ukraine           | ---            | ---           |

```terminal
CommonSecurityLog
| where DeviceVendor == "SonicWall"
| where DeviceProduct == "NSA 2700"
| where Activity has "login" or Activity has "logon"
| extend User = trim(@"""", tostring(DeviceCustomString6))
| extend User = iff(isempty(User),
                    extract(@"susr=""([^""]+)""", 1, AdditionalExtensions),
                    User)
| extend LoginStatus = case(
    DeviceEventClassID == 1080, "Success",
    Activity has "failed" or Activity has "failure" or Activity has "Unknown", "Failure",
    "Other"
  )
| summarize 
    LoginCount = count(),
    SuccessCount = countif(LoginStatus == "Success"),
    FailureCount = countif(LoginStatus == "Failure"),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by User, SourceIP
| extend Anomaly = iif(LoginCount == 1, "Single Occurrence (Potential Anomaly)", "Multiple Occurrences")
| sort by LoginCount desc
```
{: file="Frequency Analysis" }

---
## 4. Cisco ASA / AnyConnect VPN

### 4.1 Vulnerability & Exploitation Overview

Cisco ASA devices using AnyConnect VPN are vulnerable to misconfigurations, credential stuffing, and specific CVEs such as CVE-2020-3452. Threat actors may bypass MFA or leverage stolen session cookies.

### 4.2 Forensic Analysis & Log Investigation

#### How Cisco Customers Export or Share VPN Logs

##### 1. System Logging (Syslog) from ASA

Cisco ASA appliances generate detailed audit events when users connect or disconnect via AnyConnect. These are typically forwarded to a syslog server or a SIEM using standard syslog configurations.

Common message IDs include:

- **113004** – AAA user authorization successful  
- **113039** – AnyConnect parent session started  
- **722033** – First TCP service connection established (login in progress)  
- **716001** – User logs on (connection established)  
- **716002** – User logs off (disconnect)  

Reference: [Cortex Help Center](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-logs-from-Cisco-ASA-firewalls-and-AnyConnect?utm_source=chatgpt.com)

##### 2. ASDM Real-Time Log Viewer (GUI)

Administrators can use the Real-Time Log Viewer within ASDM to monitor live VPN events. By filtering on a username or public IP, they can capture login activity as it happens.

##### 3. VPN Syslogs via RAVPN Logs (Secure Access)

In Cisco Secure Access environments, logs can also be obtained via:

- AWS S3 exports in CSV format  
- These typically include fields such as `event type (CONNECTED / DISCONNECTED / FAILED), user id, public ip, session id, ASA syslog id`, and more.

Reference: [Cisco SSE Documentation](https://docs.sse.cisco.com/sse-user-guide/docs/remote-access-vpn-log-formats?utm_source=chatgpt.com)

#### What VPN Logs Typically Look Like

##### 1. ASA AnyConnect VPN via Syslog

A sample log line may appear as:
```
%ASA-5-722033: Group <GroupPolicy> User <jdoe> IP <10.0.0.1> First UDP SVC connection established for SVC session
```
{: file="Log Entry" }
These are accompanied by other syslog IDs such as:
- **113004** (authorization success)
- **113019**
- **722023**, etc.
  
##### 2. RAVPN Log Format (Secure Access)

A structured CSV example might include:
```
timestamp,hostname,...,event type,user id,...,asa syslog id,...
2024-01-16 17:48:41,fw1,...,CONNECTED,jdoe,...,722033,...
```
{: file="Log Entry" }
#### SIEM Based Investigation
> Use this query in Microsoft Sentinel to identify successful SSL VPN connections and extract key user metadata.
{: .prompt-info }
```terminal
CommonSecurityLog
| where DeviceVendor == "Cisco" and DeviceProduct == "ASA"
| where DeviceEventClassID == "113004"
// Extract server IP from `server =`
| extend AAA_Server = extract(@"server\s*=\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", 1, Message)
// Extract username from `user =`
| extend User = extract(@"user\s*=\s*([^\s]+)", 1, Message)
// Classify status
| extend LoginStatus = "AAA User Accounting Successful"
// Select key columns
| project TimeGenerated, DeviceName, DeviceAddress, DeviceEventClassID, AAA_Server, User, LoginStatus, Message
| sort by TimeGenerated desc
```
{: file="KQL Query" }

---
## 5. Citrix ADC / Gateway VPN

>**Disclaimer:** The information in this section is based mainly on open source research and has not yet been fully validated against real world Citrix ADC or Gateway logs. Treat this as preliminary and subject to refinement as more firsthand data becomes available.
{: .prompt-warning }


### 5.1 Vulnerability and Exploitation Overview

Citrix Gateway has been exploited for remote code execution, for example CVE-2019-19781.  
Successful exploitation can allow attackers to access internal networks without authentication.


### 5.2 Forensic Analysis and Log Investigation

#### How Customers Export VPN Logs

- #### Syslog Forwarding via Audit Actions
Citrix ADC appliances can forward logs such as `auth.log`, `nsvpn.log`, and `ns.log` using configurable `-managementlog` syslog parameters available from version **14.1 build 12.30+**.  
Supported levels include Access, NSMGMT, or ALL.  
Reference: Citrix Community.

- #### Local Log Access (ns.log and newnslog.*)
VPN events are written locally to:`/var/log/ns.log` and rotated files under `/var/nslog/newnslog.*`.

  These include authentication events, SSLVPN entries, and configuration changes.  
  Reference: [Citrix Community](https://community.citrix.com/forums/topic/334-netscaler-appliances-logging/?utm_source=chatgpt.com).

- #### Citrix ADM or Gateway Insight APIs
For session level data like connect and disconnect times or client IPs, customers often export data from:
  - ADM Gateway Insight UI  
  - ADM Insight APIs

  This is used to collect terminated session history.

## What Exported VPN Logs Typically Look Like

Citrix ADC VPN logs are structured with identifiable fields. Below are example events.
```plaintext
Nov 28 12:17:01 ... SSLVPN LOGIN ... Context user@domain – SessionId: 75 – User sjacobs – Client_ip 100.x.x.x – Nat_ip "Mapped Ip" – Vserver 10.x.x.x:443 – SSLVPN_client_type Agent – Group(s) "N/A"
```
{: file="Sample Log" }
  - Contains embedded details like User, Client_ip, Vserver, etc.
  - Useful for extracting username and client source IP

Another example:
```
SSLVPN HTTPREQUEST ... Context wireless@192.168.1.50 – SessionId: 5– User wireless – Client_ip 192.168.1.50 – Nat_ip ... – Access Allowed
```
{: file="Sample Log" }
These logs typically follow this pattern:
```
<timestamp> … Type_of_event ID : Context <user>@<ip> – SessionId: … – User <username> – Client_ip <ip> – …
```
{: file="Sample Log" }
#### SIEM Based Investigation
> Use this query in Microsoft Sentinel to identify successful SSL VPN connections and extract key user metadata.
{: .prompt-info }
```terminal
CommonSecurityLog
| where DeviceVendor has "Citrix" or DeviceProduct has "ADC"
| where Message has "SSLVPN LOGIN" or Message has "SSLVPN"
| extend
    RawMsg = Message,
    Username = extract(@"User\s+([^–\s]+)", 1, RawMsg),
    ClientIP = extract(@"Client_ip\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", 1, RawMsg),
    SessionId = extract(@"SessionId:\s*([0-9]+)", 1, RawMsg),
    EventType = extract(@"SSLVPN\s+(\w+)", 1, RawMsg)
| project TimeGenerated, EventType, Username, ClientIP, SessionId, RawMsg
| sort by TimeGenerated desc
```
{: file="KQL Query" }
---
## 6. Conclusion
Effective VPN forensic investigation requires a combination of vulnerability awareness, log correlation, and anomaly detection. Regular patching, MFA enforcement, and geo-based access restrictions significantly reduce risk.
