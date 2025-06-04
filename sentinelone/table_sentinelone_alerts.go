package sentinelone

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	sdkproto "github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	plugin "github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

type SentinelOneAlertFull struct {
	AlertID        string                 `json:"-"`
	RuleName       string                 `json:"-"`
	Severity       string                 `json:"-"`
	IncidentStatus string                 `json:"-"`
	CreatedAt      *time.Time             `json:"-"`
	ReportedAt     *time.Time             `json:"-"`
	SourceIP       string                 `json:"-"`
	DestinationIP  string                 `json:"-"`
	AgentUUID      string                 `json:"-"`
	Raw            map[string]interface{} `json:"-"`
}

func (a *SentinelOneAlertFull) UnmarshalJSON(b []byte) error {
	var tmp map[string]interface{}
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	a.Raw = tmp

	if ai, ok := tmp["alertInfo"].(map[string]interface{}); ok {
		if v, ok := ai["alertId"].(string); ok {
			a.AlertID = v
		}
		if v, ok := ai["createdAt"].(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
				a.CreatedAt = &t
			}
		}
		if v, ok := ai["reportedAt"].(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
				a.ReportedAt = &t
			}
		}
		if v, ok := ai["incidentStatus"].(string); ok {
			a.IncidentStatus = v
		}
		if v, ok := ai["srcIp"].(string); ok {
			a.SourceIP = v
		}
		if v, ok := ai["dstIp"].(string); ok {
			a.DestinationIP = v
		}
	}

	if ri, ok := tmp["ruleInfo"].(map[string]interface{}); ok {
		if v, ok := ri["name"].(string); ok {
			a.RuleName = v
		}
		if v, ok := ri["severity"].(string); ok {
			a.Severity = v
		}
	}

	if adi, ok := tmp["agentDetectionInfo"].(map[string]interface{}); ok {
		if v, ok := adi["uuid"].(string); ok {
			a.AgentUUID = v
		}
	}

	return nil
}

func tableSentinelOneAlerts(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "sentinelone_alert",
		Description: "Alerts generati da SentinelOne (cloud-detection).",
		List: &plugin.ListConfig{
			Hydrate: listSentinelOneAlerts,
		},
		Columns: []*plugin.Column{
			{Name: "alert_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertID")},
			{Name: "rule_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleName")},
			{Name: "severity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Severity")},
			{Name: "incident_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("IncidentStatus")},
			{Name: "created_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("CreatedAt")},
			{Name: "reported_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("ReportedAt")},
			{Name: "source_ip", Type: sdkproto.ColumnType_INET, Transform: transform.FromField("SourceIP")},
			{Name: "destination_ip", Type: sdkproto.ColumnType_INET, Transform: transform.FromField("DestinationIP")},
			{Name: "agent_uuid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentUUID")},
			{Name: "raw", Type: sdkproto.ColumnType_JSON, Description: "Full JSON object for the alert."},
		},
	}
}

func (t *SentinelOneClient) ListAlertsRaw() ([]interface{}, map[string]interface{}, []interface{}, error) {
	var allData []interface{}
	var lastPagination map[string]interface{}
	var lastErrors []interface{}
	cursor := ""

	for {
		params := map[string]string{
			"limit": "1000", // maximum supported limit per page
		}
		if cursor != "" {
			params["cursor"] = cursor
		}

		fullURL, err := t.BuildURL("/web/api/v2.1/cloud-detection/alerts", params)
		if err != nil {
			return nil, nil, nil, err
		}

		body, err := t.Get(fullURL)
		if err != nil {
			return nil, nil, nil, err
		}

		var resp struct {
			Data       []interface{}          `json:"data"`
			Pagination map[string]interface{} `json:"pagination"`
			Errors     []interface{}          `json:"errors"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse JSON: %w", err)
		}

		allData = append(allData, resp.Data...)
		lastPagination = resp.Pagination
		lastErrors = resp.Errors

		nextCursor, _ := resp.Pagination["nextCursor"].(string)
		if nextCursor == "" || nextCursor == cursor {
			break
		}
		cursor = nextCursor
	}

	return allData, lastPagination, lastErrors, nil
}

func listSentinelOneAlerts(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	client, err := Connect(ctx, d)
	if err != nil {
		return nil, err
	}

	rawData, _, _, err := client.ListAlertsRaw()
	if err != nil {
		return nil, err
	}

	for _, item := range rawData {
		if m, ok := item.(map[string]interface{}); ok {
			b, _ := json.Marshal(m)
			var alert SentinelOneAlertFull
			if err := json.Unmarshal(b, &alert); err != nil {
				plugin.Logger(ctx).Error("listSentinelOneAlerts", "unmarshal_error", err)
				continue
			}
			d.StreamListItem(ctx, alert)
			if d.RowsRemaining(ctx) == 0 {
				break
			}
		}
	}

	return nil, nil
}
