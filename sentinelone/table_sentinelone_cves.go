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
		Name:        "sentinelone_cves",
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
			{Name: "application", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Application")},
			{Name: "application_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ApplicationName")},
			{Name: "application_vendor", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ApplicationVendor")},
			{Name: "application_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ApplicationVersion")},
			{Name: "base_score", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("BaseScore")},
			{Name: "cve_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("CveID")},
			{Name: "cvss_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("CvssVersion")},
			{Name: "days_detected", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("DaysDetected")},
			{Name: "detection_date", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("DetectionDate")},
			{Name: "endpoint_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("EndpointID")},
			{Name: "endpoint_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("EndpointName")},
			{Name: "endpoint_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("EndpointType")},
			{Name: "id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ID")},
			{Name: "last_scan_date", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("LastScanDate")},
			{Name: "last_scan_result", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("LastScanResult")},
			{Name: "os_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OSType")},
			{Name: "published_date", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("PublishedDate")},
			{Name: "severity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Severity")},
			{Name: "status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Status")},
		},
	}
}

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
