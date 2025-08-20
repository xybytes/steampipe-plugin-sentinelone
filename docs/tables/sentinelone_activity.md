---
title: "Steampipe Table: sentinelone_activities - Query SentinelOne Activities using SQL"
description: "Query SentinelOne activity to track and analyze operational events, system changes, and security actions across your endpoints."
---

# Table: sentinelone_activities - Query SentinelOne Activities using SQL

SentinelOne Activities represent recorded actions, events, and operational changes within the SentinelOne platform. These activities include security-related events such as detections, mitigations, policy changes, and administrative actions. Monitoring activities provides deep visibility into what is happening in your environment, helping security teams maintain compliance, detect anomalies, and audit system behaviors.

Each activity record includes detailed information such as activity type, associated agent and site, timestamps, related threat or alert IDs, and context-rich metadata (e.g., IP addresses, DNS requests, process information). This enables a comprehensive understanding of both security and administrative actions.

## Table Usage Guide

The `sentinelone_activity` table allows security analysts to query historical and real-time activity data, enabling organizations to audit operational changes for compliance, track detection and mitigation workflows, and uncover unusual patterns or suspicious behavior across their environment.

## Examples

### Basic Info
Explore recent activities to understand what actions occurred, when, and on which devices. This helps maintain visibility across security operations.

```sql+postgres
select
  id,
  activity_type,
  description,
  agent_id,
  site_name,
  created_at
from
  sentinelone_activity;
```

```sql+sqlite
select
  id,
  activity_type,
  description,
  agent_id,
  site_name,
  created_at
from
  sentinelone_activity;
```

### Investigate activities linked to threats
Discover activities linked to detected threats to improve incident response and trace the sequence of events. Correlating activities with threats provides crucial context, allowing security teams to understand how the threat was handled, which actions were taken, and whether any follow-up steps are required to fully remediate the issue.

```sql+postgres
select
  id,
  activity_type,
  description,
  threat_id,
  agent_id,
  created_at
from
  sentinelone_activity
where
  threat_id is not null
order by
  created_at desc;
```

```sql+sqlite
select
  id,
  activity_type,
  description,
  threat_id,
  agent_id,
  created_at
from
  sentinelone_activity
where
  threat_id is not null
order by
  created_at desc;
```

### Top activity types in the last 7 days
Gain visibility into the most common activity types occurring in your environment to identify patterns, monitor operational trends, and detect anomalies. Understanding which actions are performed most frequently helps prioritize monitoring efforts and ensures that unusual or high-risk activities stand out for further investigation.

```sql+postgres
select
  activity_type,
  count(*) as activity_count
from
  sentinelone_activity
where
  created_at >= (current_timestamp - interval '7 days')
group by
  activity_type
order by
  activity_count desc;
```

```sql+sqlite
select
  activity_type,
  count(*) as activity_count
from
  sentinelone_activity
where
  created_at >= datetime('now', '-7 days')
group by
  activity_type
order by
  activity_count desc;
```