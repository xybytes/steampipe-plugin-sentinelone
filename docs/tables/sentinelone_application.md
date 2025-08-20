---
title: "Steampipe Table: sentinelone_application - Query SentinelOne Applications using SQL"
description: "Allows users to query SentinelOne Applications, providing detailed information about installed software and application risk across the SentinelOne platform."
---

# Table: sentinelone_application - Query SentinelOne Applications using SQL

SentinelOne Applications provide a comprehensive view of software installed across protected endpoints. By leveraging SentinelOne’s Application Risk capabilities, each application is analyzed for vulnerabilities, risk levels, and compliance issues. This information is critical for identifying potentially vulnerable or unauthorized applications that could increase your attack surface.

Each record contains details such as application name, version, publisher, risk level, associated agent, and operating system. Security teams can use this data to maintain software inventory, enforce compliance policies, detect outdated or risky applications, and strengthen endpoint security posture.

## Table Usage Guide

The `sentinelone_application` table provides centralized visibility into all installed applications within your environment. Use this table to audit installed software, identify applications with elevated risk levels, and track software versions across endpoints for compliance and vulnerability management.

## Examples

### Basic info
View a list of installed applications along with their version, publisher, and associated endpoint to maintain visibility over your software inventory.

```sql+postgres
select
  name,
  vendor,
  detection_date,
  endpoint_count
from
  sentinelone_application;
```

```sql+sqlite
select
  name,
  vendor,
  detection_date,
  endpoint_count
from
  sentinelone_application;
```

### Identify applications with known vulnerabilities
Find applications that have associated CVEs, which may require patching or removal.

```sql+postgres
select
  name,
  vendor,
  cve_count,
  highest_severity,
  highest_nvd_base_score
from
  sentinelone_application
where
  cve_count > 0;
```

```sql+sqlite
select
  name,
  vendor,
  cve_count,
  highest_severity,
  highest_nvd_base_score
from
  sentinelone_application
where
  cve_count > 0;
```

### Applications with critical severity
Retrieve applications marked with the highest severity level to prioritize remediation.

```sql+postgres
select
  name,
  vendor,
  highest_severity,
  cve_count,
  endpoint_count
from
  sentinelone_application
where
  highest_severity = 'HIGH'
  and cve_count > 0
order by
  endpoint_count desc;
```

```sql+sqlite
select
  name,
  vendor,
  highest_severity,
  cve_count,
  endpoint_count
from
  sentinelone_application
where
  highest_severity = 'HIGH'
  and cve_count > 0
order by
  endpoint_count desc;
```

