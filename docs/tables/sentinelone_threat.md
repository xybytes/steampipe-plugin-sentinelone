---
title: "Steampipe Table: sentinelone_threat - Query SentinelOne Threats using SQL"
description: "Query detailed information about confirmed or suspected malicious activities detected across the SentinelOne platform."
---

# Table: sentinelone_threat - Query SentinelOne Threats using SQL

SentinelOne Threats represent malicious or suspicious activities identified by the SentinelOne platform using AI-driven analytics, behavioral detection, and Indicators of Compromise (IOCs). These detections are crucial for preventing breaches and ensuring endpoint security. Each threat record contains rich context such as threat ID, classification, confidence level, detection method, affected endpoints, related files and processes, and mitigation status. This enables security teams to assess the impact of a threat, determine response urgency, and take corrective measures effectively.

## Table Usage Guide

The `sentinelone_threat` table helps security teams gain visibility into all detected threats within their environment. It supports investigations into the nature and scope of threats, helping organizations maintain a strong security posture and respond rapidly to potential compromises.

## Examples

### Basic info
View essential details of threats detected in your environment, including threat name, detection time, confidence level, and associated agent information. This helps you understand which endpoints are impacted and prioritize investigation.

```sql+postgres
select
  threat_id,
  threat_name,
  confidence_level,
  sha256,
  identified_at,
  agent_computer_name,
  site_name
from
  sentinelone_threat
```

### Unresolved Threats
Identify threats that remain unresolved to ensure timely remediation and prevent potential escalation. These unresolved threats could indicate ongoing malicious activity or incomplete mitigation, making them high-priority targets for investigation and response. Monitoring this data helps security teams close gaps before attackers exploit them further.

```sql+postgres
select
  threat_id,
  threat_name,
  confidence_level,
  sha256,
  identified_at,
  incident_status,
  agent_computer_name,
  site_name
from
  sentinelone_threat
where
  incident_status != 'Resolved'
order by
  identified_at desc;
```

### Threats by Detection Type
Analyze threats based on their detection type to gain insight into how different attack vectors are being identified within your environment. Understanding which detection methods—such as behavioral AI, static analysis, or cloud intelligence—are most commonly triggered can help fine-tune security policies, optimize detection strategies, and strengthen your overall defense posture.

```sql+postgres
select
  detection_type,
  count(*) as total_threats
from
  sentinelone_threat
group by
  detection_type
order by
  total_threats desc;
```
