package sentinelone

import (
	"context"
	"encoding/json"
	"time"

	sdkproto "github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

type SentinelOneApplication struct {
	ApplicationId       string    `json:"applicationId"`
	CveCount            int       `json:"cveCount"`
	DaysDetected        int       `json:"daysDetected"`
	DetectionDate       time.Time `json:"detectionDate"`
	EndpointCount       int       `json:"endpointCount"`
	Estimate            bool      `json:"estimate"`
	HighestNvdBaseScore string    `json:"highestNvdBaseScore"`
	HighestSeverity     string    `json:"highestSeverity"`
	Name                string    `json:"name"`
	Vendor              string    `json:"vendor"`
}

func tableSentinelOneApplications(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "sentinelone_applications",
		Description: "Get data for each version of all applications.",
		List:        &plugin.ListConfig{Hydrate: listSentinelOneApplications},
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
			{Name: "application_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ApplicationId")},
			{Name: "cve_count", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("CveCount")},
			{Name: "days_detected", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("DaysDetected")},
			{Name: "detection_date", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("DetectionDate")},
			{Name: "endpoint_count", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("EndpointCount")},
			{Name: "estimate", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("Estimate")},
			{Name: "highest_nvd_base_score", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("HighestNvdBaseScore")},
			{Name: "highest_severity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("HighestSeverity")},
			{Name: "name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Name")},
			{Name: "vendor", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Vendor")},
		},
	}
}

// Retrieves paginated threat data
func (t *SentinelOneClient) ListApplicationsRaw(ctx context.Context, d *plugin.QueryData) (
	[]interface{},
	map[string]interface{},
	[]interface{},
	error,
) {
	// passing in: the request context, the query data (for SQL LIMIT), the API endpoint, the maximum page size per HTTP call
	return t.fetchPaginatedData(ctx, d, "/web/api/v2.1/application-management/risks/applications", 1000)
}

func listSentinelOneApplications(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	client, err := Connect(ctx, d)
	if err != nil {
		return nil, err
	}

	rawData, _, _, err := client.ListApplicationsRaw(ctx, d)
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
		var app SentinelOneApplication
		if err := json.Unmarshal(b, &app); err != nil {
			plugin.Logger(ctx).Error("listSentinelOneApplications", "unmarshal_error", err)
			continue
		}

		// Stream the item into Steampipe
		d.StreamListItem(ctx, app)

		// Stop if the query’s SQL LIMIT has been reached
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	return nil, nil
}
