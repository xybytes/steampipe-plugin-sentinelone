---
title: "Steampipe Table: sentinelone_cve - Query SentinelOne CVEs using SQL"
description: "Query SentinelOne CVEs to retrieve detailed information about vulnerabilities detected across your environment, including CVSS scores, severity levels, and associated applications."
---

# Table: sentinelone_cve - Query SentinelOne CVEs using SQL

The `sentinelone_cve` table provides detailed information about Common Vulnerabilities and Exposures (CVEs) associated with applications and endpoints monitored by SentinelOne. This data is essential for vulnerability management, risk assessment, and patching strategies.

Each record includes details such as CVE ID, severity, CVSS base score, detection date, associated application and version, endpoint information, and published date. These insights help security teams prioritize remediation efforts and maintain a strong security posture.

## Table Usage Guide

Use the `sentinelone_cve` table to identify vulnerabilities impacting your applications and endpoints, analyze CVSS scores and severity levels for prioritization, and monitor vulnerability detection trends over time. This data supports compliance requirements and proactive vulnerability management.

## Examples

### Basic info
Retrieve CVEs along with application name, vendor, severity, and CVSS base score.

```sql+postgres
select
  cve_id,
  application_name,
  application_vendor,
  severity,
  base_score
from
  sentinelone_cve
order by
  base_score desc
limit 10;
```

```sql+sqlite
select
  cve_id,
  application_name,
  application_vendor,
  severity,
  base_score
from
  sentinelone_cve
order by
  base_score desc
limit 10;
```

### Endpoints with the most vulnerabilities
Detect which endpoints have the highest number of detected CVEs.

```sql+postgres
select
  endpoint_name,
  count(*) as cve_count
from
  sentinelone_cve
group by
  endpoint_name
order by
  cve_count desc;
```

```sql+sqlite
select
  endpoint_name,
  count(*) as cve_count
from
  sentinelone_cve
group by
  endpoint_name
order by
  cve_count desc;
```

### CVEs by operating system
Analyze vulnerabilities grouped by OS type for targeted patching strategies.

```sql+postgres
select
  os_type,
  count(*) as cve_count
from
  sentinelone_cve
group by
  os_type
order by
  cve_count desc;
```

```sql+sqlite
select
  os_type,
  count(*) as cve_count
from
  sentinelone_cve
group by
  os_type
order by
  cve_count desc;
```