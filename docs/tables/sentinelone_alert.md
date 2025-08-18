---
title: "Steampipe Table: sentinelone_alert - Query SentinelOne Alerts using SQL"
description: "Allows users to query SentinelOne Alerts, providing detailed information about security incidents detected across the SentinelOne platform."
---

# Table: sentinelone_alert - Query SentinelOne Alerts using SQL

SentinelOne Alerts is a feature within the SentinelOne platform that provides a comprehensive list of security alerts. It leverages advanced AI and Indicator of Compromise (IOC) sweeps to detect malicious activities and suspicious behaviors. Each alert includes detailed information such as the alert ID, source and destination IP addresses, DNS details, registry paths, file hashes, and OS information. This rich context enables security teams to gain a full understanding of the incident and take effective response actions.

## Table Usage Guide

The `sentinelone_alert` table provides detailed insights into security alerts within the SentinelOne platform. As a cybersecurity analyst, you can use this table to investigate incidents, analyze attack indicators, and understand ongoing or past malicious activities for effective threat response.

## Examples

### Basic info
Explore which alerts were made in your system, when they were identified, and the devices they originated from. This is particularly useful for understanding the security landscape of your network and identifying potential vulnerabilities.

```sql+postgres
select
  alert_id,
  src_ip,
  dst_ip,
  target_proc_name,
  target_file_hash_sha1
from
  sentinelone_alert
```

### List alerts by a specific target SHA-256 hash
Retrieve recent security alerts associated with a specific file hash. This query helps you identify potential threats related to that file within the past three months, enabling proactive threat hunting and improved incident response.

```sql+postgres
select
  alert_id,
  src_ip,
  dst_ip,
  target_proc_name,
  target_file_hash_sha256
from
  sentinelone_alert
where
  target_file_hash_sha256 = '9001567e2025f83c936b8746fd3b01e44572f70d8ddec39b75b9459f7e5089c8';
```

### List open alerts from the last 4 days
Determine the areas in which open detections have occurred in the past four days, which can help in identifying potential security threats and ensuring timely response to the same.

```sql+postgres
select
  src_ip,
  dst_ip,
  indicator_name,
  incident_status,
  created_at
from
  sentinelone_alerts
where
  incident_status = 'open'
  and created_at >= (current_timestamp - interval '4 days')
order by
  created_at desc
```
