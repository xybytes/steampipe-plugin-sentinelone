---
title: "Steampipe Table: sentinelone_note - Query SentinelOne Threat Notes using SQL"
description: "Query SentinelOne notes attached to threats, providing details for incident documentation and investigation."
---

# Table: sentinelone_note - Query SentinelOne Threat Notes using SQL

The `sentinelone_note` table provides access to notes associated with specific threats in SentinelOne. Notes are often used by analysts to document investigations, remediation steps, or incident details. This feature enables security teams to maintain comprehensive records for threat response, forensic analysis, and compliance reporting.

Each record includes details such as the note text, creator information, timestamps for creation and updates, and the associated threat ID. By querying this data, teams can improve collaboration and ensure accurate incident documentation.

## Table Usage Guide

Use the `sentinelone_note` table to review, audit, and manage analyst notes tied to security threats. This helps maintain detailed incident history, support compliance, and streamline handoffs between security teams during investigations.

## Examples

### List notes for a specific threat
Retrieve all notes related to a given threat ID for better incident context.

```sql+postgres
select 
  threat_id, 
  text
from 
  sentinelone_note
where 
  threat_id = '2006880807819281256';
```
