package sentinelone

import (
	"context"
	"encoding/json"
	"time"

	sdkproto "github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

type SentinelOneVulnerability struct {
	Application        string    `json:"application"`
	ApplicationName    string    `json:"applicationName"`
	ApplicationVendor  string    `json:"applicationVendor"`
	ApplicationVersion string    `json:"applicationVersion"`
	BaseScore          string    `json:"baseScore"`
	CveID              string    `json:"cveId"`
	CvssVersion        string    `json:"cvssVersion"`
	DaysDetected       int       `json:"daysDetected"`
	DetectionDate      time.Time `json:"detectionDate"`
	EndpointID         string    `json:"endpointId"`
	EndpointName       string    `json:"endpointName"`
	EndpointType       string    `json:"endpointType"`
	ID                 string    `json:"id"`
	LastScanDate       time.Time `json:"lastScanDate"`
	LastScanResult     string    `json:"lastScanResult"`
	OSType             string    `json:"osType"`
	PublishedDate      time.Time `json:"publishedDate"`
	Severity           string    `json:"severity"`
	Status             string    `json:"status"`
}

func tableSentinelOneCVEs(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "sentinelone_cve",
		Description: "Get the CVE vulnerability data for each CVE.",
		List:        &plugin.ListConfig{Hydrate: listSentinelOneCVEs},
		// API Rate Liming
		// 200 requests from the same IP address every 100 seconds
		// 5,000,000 bytes of total request size for each operation every 500,000 seconds (≈138.9 h)
		// 40 concurrent requests for the same API token
		HydrateConfig: []plugin.HydrateConfig{
			{
				Func:           listSentinelOneAgents,
				MaxConcurrency: 40,
			},
		},
		Columns: []*plugin.Column{
			{Name: "application", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Application"), Description: "Application identifier associated with this CVE."},
			{Name: "application_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ApplicationName"), Description: "Name of the application affected by this CVE."},
			{Name: "application_vendor", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ApplicationVendor"), Description: "Vendor of the affected application."},
			{Name: "application_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ApplicationVersion"), Description: "Version of the application where the CVE was detected."},
			{Name: "base_score", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("BaseScore"), Description: "CVSS base score for this vulnerability."},
			{Name: "cve_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("CveID"), Description: "Unique identifier of the CVE."},
			{Name: "cvss_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("CvssVersion"), Description: "Version of the CVSS specification used."},
			{Name: "days_detected", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("DaysDetected"), Description: "Number of days since this CVE was first detected."},
			{Name: "detection_date", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("DetectionDate"), Description: "Timestamp when this CVE was first detected."},
			{Name: "endpoint_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("EndpointID"), Description: "Identifier of the endpoint where the CVE was found."},
			{Name: "endpoint_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("EndpointName"), Description: "Name of the endpoint where the CVE was found."},
			{Name: "endpoint_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("EndpointType"), Description: "Type of endpoint (e.g. workstation, server)."},
			{Name: "id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ID"), Description: "Unique record identifier for this CVE entry."},
			{Name: "last_scan_date", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("LastScanDate"), Description: "Timestamp of the most recent scan for this CVE."},
			{Name: "last_scan_result", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("LastScanResult"), Description: "Result status of the most recent scan."},
			{Name: "os_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OSType"), Description: "Operating system type of the affected endpoint."},
			{Name: "published_date", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("PublishedDate"), Description: "Official publication date of the CVE."},
			{Name: "severity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Severity"), Description: "Severity rating of the CVE."},
			{Name: "status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Status"), Description: "Current status of the CVE (e.g. open, mitigated)."},
		},
	}
}

// retrieves paginated threat data
func (c *SentinelOneClient) ListCVEsRaw(ctx context.Context, d *plugin.QueryData) (
	[]interface{},
	map[string]interface{},
	[]interface{},
	error,
) {
	return c.fetchPaginatedData(ctx, d, "/web/api/v2.1/application-management/risks", 1000)
}

func listSentinelOneCVEs(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	client, err := Connect(ctx, d)
	if err != nil {
		return nil, err
	}

	rawData, _, _, err := client.ListCVEsRaw(ctx, d)
	if err != nil {
		return nil, err
	}

	for _, item := range rawData {
		// Exit if context has been cancelled
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		b, _ := json.Marshal(m)

		var v SentinelOneVulnerability
		if err := json.Unmarshal(b, &v); err != nil {
			plugin.Logger(ctx).Error("listSentinelOneCVEs", "unmarshal_error", err)
			continue
		}

		// Stream the item into Steampipe
		d.StreamListItem(ctx, v)

		// Stop if the query’s SQL LIMIT has been reached
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	return nil, nil
}
