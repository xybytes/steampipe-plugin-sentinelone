---
title: "Steampipe Table: sentinelone_timeline - Query Threat Timeline Events using SQL"
description: "Query detailed timeline events related to SentinelOne threats for forensic and incident response investigations."
---

# Table: sentinelone_timeline - Query Threat Timeline Events using SQL

The `sentinelone_timeline` table provides detailed insights into the sequence of events related to individual threats detected by SentinelOne. This timeline includes important operational context such as task execution, remediation steps, account activity, and system-level changes.

Each timeline entry is associated with a specific threat and includes timestamps, agent and account identifiers, primary and secondary descriptions, as well as detailed metadata from the source of the event. This chronological view is critical for incident response, helping analysts reconstruct the full lifecycle of a threat and evaluate response effectiveness.

## Table Usage Guide

Use the `sentinelone_timeline` table to:
- Reconstruct the full sequence of actions and events linked to a specific threat.
- Track changes, tasks, or user interventions throughout the threat lifecycle.
- Correlate forensic details across endpoints, accounts, and detection scopes.

## Examples

### Show the timeline for a specific threat
List all events tied to a given `threat_id` in chronological order.

```sql+postgres
select
  threat_id,
  created_at,
  primary_description,
  secondary_description
from
  sentinelone_timeline
where
  threat_id = '5664677667902588444';
```

```sql+sqlite
select
  threat_id,
  created_at,
  primary_description,
  secondary_description
from
  sentinelone_timeline
where
  threat_id = '5664677667902588444';
```

### Highlight timeline entries with user involvement
This query helps identify timeline events where user interaction played a role, whether through direct actions such as threat mitigation, policy changes, or command execution. By isolating events tied to specific user accounts, security teams can better understand human involvement in the lifecycle of a threat, verify authorized activity, and support audit and compliance requirements.

```sql+postgres
select
  threat_id,
  created_at,
  data_user_name,
  primary_description
from
  sentinelone_timeline
where
  threat_id = '5664677667902588444'
  and data_user_name is not null;
```

```sql+sqlite
select
  threat_id,
  created_at,
  data_user_name,
  primary_description
from
  sentinelone_timeline
where
  threat_id = '5664677667902588444'
  and data_user_name is not null;
```