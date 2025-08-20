---
title: "Steampipe Table: sentinelone_agent - Query SentinelOne Agents using SQL"
description: "Allows users to query SentinelOne Agents, providing detailed information about agents across the SentinelOne platform."
---

# Table: sentinelone_agent - Query SentinelOne Agents using SQL

SentinelOne Agents form the core of endpoint protection within the SentinelOne platform. Installed on endpoints, these agents continuously monitor system activity, applying behavioral AI and machine learning to detect and mitigate threats in real time. Each agent collects and reports comprehensive data, including device details, operating system information, network configuration, policy status, and security posture. This centralized visibility empowers security teams to track endpoint compliance, identify vulnerabilities, and respond proactively to emerging threats.

## Table Usage Guide

The `sentinelone_agent` table provides detailed information about all SentinelOne agents deployed across your environment. Use this table to monitor endpoint status, review operating system and agent versions, check policy assignments, and identify potential security gaps, ensuring comprehensive visibility and control over your endpoints.

## Examples

### Basic info
Explore which agents are deployed in your environment, their current status, and key details such as operating system, version, and associated sites. This information is essential for maintaining endpoint visibility, ensuring policy compliance, and identifying devices that may require attention.

```sql+postgres
select
  account_id,
  computer_name,
  agent_version,
  os_name,
from
  sentinelone_agent;
```

```sql+sqlite
select
  account_id,
  computer_name,
  agent_version,
  os_name,
from
  sentinelone_agent;
```

### Identify agents with active threats
Identify agents currently reporting one or more active threats. These endpoints may be compromised or under attack and should be prioritized for investigation and remediation. Monitoring this helps ensure threats are addressed before they can spread laterally or cause further damage.

```sql+postgres
select
  computer_name,
  os_name,
  site_name,
  active_threats,
  last_active_date
from
  sentinelone_agent
where
  active_threats > 0
order by
  active_threats desc;
```

```sql+sqlite
select
  computer_name,
  os_name,
  site_name,
  active_threats,
  last_active_date
from
  sentinelone_agent
where
  active_threats > 0
order by
  active_threats desc;
```

### Inactive or offline agents
List agents that haven’t been active in the last 7 days, which might indicate unmanaged or compromised devices.

```sql+postgres
select
  computer_name,
  os_name,
  site_name,
  last_active_date
from
  sentinelone_agent
where
  last_active_date < (current_timestamp - interval '7 days')
order by
  last_active_date asc;
```

```sql+sqlite
select
  computer_name,
  os_name,
  site_name,
  last_active_date
from
  sentinelone_agent
where
  last_active_date < datetime('now', '-7 days')
order by
  last_active_date asc;
```




