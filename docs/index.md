---
organization: Turbot
category: ["security"]
brand_color: "#844FBA"
display_name: SentinelOne
name: sentinelone
description: SentinelOne is an autonomous cybersecurity platform that provides comprehensive protection against various cyber threats.
og_description: Query SentinelOne data with SQL! Open source CLI. No DB required.
og_image: "/images/plugins/xybytes/sentinelone-social-graphic.png"
icon_url: "/images/plugins/xybytes/sentinelone.svg"
engines: ["steampipe", "sqlite", "postgres", "export"]
---

# SentinelOne + Steampipe

[Steampipe](https://steampipe.io) is an open-source zero-ETL engine to instantly query cloud APIs using SQL.

[SentinelOne](https://sentinelone.com) provides cloud workload and endpoint security, threat intelligence, and cyberattack response services.

For example:

```sql
select
  alert_id,
  src_ip,
  dst_ip
from 
  sentinelone_alerts
limit 50;
```

## Documentation

- **[Table definitions & examples →](/plugins/xybytes/sentinelone/tables)**

## Get started

### Install

Download and install the latest SentinelOne plugin:

```shell
steampipe plugin install xybytes/sentinelone
```

### Configuration

Installing the latest sentinelone plugin will create a config file (`~/.steampipe/config/sentinelone.spc`) with a single connection named `sentinelone`:

```hcl
connection "sentinelone" {
  plugin     = "sentinelone"

  # SentinelOne client ID
  # Can also be set with the SENTINELONE_CLIENT_ID environment variable
  # client_id        = "companyname"
  
  # SentinelOne JWT Token
  # Can also be set with the SENTINELONE_API_TOKEN environment variable
  # api_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"
}
```

- `client_id` - (Required) The client ID. Can also be set with the `SENTINELONE_CLIENT_ID` environment variable.
- `api_token` - (Required) The API Access Token. Can also be set with the `SENTINELONE_API_TOKEN` environment variable.
