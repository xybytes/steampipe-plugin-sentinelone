package sentinelone

import (
	"context"
	"encoding/json"
	"fmt"

	sdkproto "github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

type SentinelOneTimelineFull struct {
	ID            string `json:"id"`
	AccountId     string `json:"accountId"`
	AgentId       string `json:"agentId"`
	ThreatId      string `json:"threatId"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
	PrimaryDesc   string `json:"primaryDescription"`
	SecondaryDesc string `json:"secondaryDescription"`
	Data          Data   `json:"data"`
}

type Data struct {
	AccountName          string `json:"accountName"`
	AgentUpdatedVersion  string `json:"agentUpdatedVersion"`
	ComputerName         string `json:"computerName"`
	ExternalServiceId    string `json:"externalServiceId"`
	FullScopeDetails     string `json:"fullScopeDetails"`
	FullScopeDetailsPath string `json:"fullScopeDetailsPath"`
	GroupName            string `json:"groupName"`
	IPAddress            string `json:"ipAddress"`
	RealUser             string `json:"realUser"`
	ScopeLevel           string `json:"scopeLevel"`
	ScopeName            string `json:"scopeName"`
	SiteName             string `json:"siteName"`
	SourceType           string `json:"sourceType"`
	TaskId               string `json:"taskId"`
	UserName             string `json:"userName"`
}

func tableSentinelOneTimeline(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "sentinelone_timeline",
		Description: "Timeline of activities related to threats.",
		List: &plugin.ListConfig{
			Hydrate: listSentinelOneTimeline,
			KeyColumns: []*plugin.KeyColumn{
				{
					Name:    "threat_id",
					Require: plugin.Required,
				},
			},
		},
		Columns: []*plugin.Column{
			{Name: "threat_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatId")},
			{Name: "id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ID")},
			{Name: "account_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AccountId")},
			{Name: "agent_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentId")},
			{Name: "created_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("CreatedAt")},
			{Name: "updated_at", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("UpdatedAt")},
			{Name: "primary_description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("PrimaryDesc")},
			{Name: "secondary_description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SecondaryDesc")},

			//Data
			{Name: "data_account_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.AccountName")},
			{Name: "data_agent_updated_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.AgentUpdatedVersion")},
			{Name: "data_computer_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ComputerName")},
			{Name: "data_external_service_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ExternalServiceId")},
			{Name: "data_full_scope_details", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.FullScopeDetails")},
			{Name: "data_full_scope_details_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.FullScopeDetailsPath")},
			{Name: "data_group_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.GroupName")},
			{Name: "data_ip_address", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.IPAddress")},
			{Name: "data_real_user", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RealUser")},
			{Name: "data_scope_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ScopeLevel")},
			{Name: "data_scope_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ScopeName")},
			{Name: "data_site_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SiteName")},
			{Name: "data_source_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceType")},
			{Name: "data_task_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TaskId")},
			{Name: "data_user_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.UserName")},
		},
	}
}

func (t *SentinelOneClient) ListTimelineRaw(ctx context.Context, d *plugin.QueryData) (
	[]interface{},
	map[string]interface{},
	[]interface{},
	error,
) {
	threatId := d.EqualsQuals["threat_id"].GetStringValue()
	if threatId == "" {
		return nil, nil, nil, fmt.Errorf("missing required field: threat_id")
	}

	endpoint := fmt.Sprintf("/web/api/v2.1/threats/%s/timeline", threatId)
	return t.fetchPaginatedData(ctx, d, endpoint, 1000)
}

// Stream each timeline entry into Steampipe, respecting context cancellation and SQL LIMIT.
func listSentinelOneTimeline(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	// Establish the API client
	client, err := Connect(ctx, d)
	if err != nil {
		return nil, err
	}

	// Fetch rawData
	rawData, _, _, err := client.ListTimelineRaw(ctx, d)
	if err != nil {
		return nil, err
	}

	// Iterate over each raw item
	for _, item := range rawData {
		// Exit early if the context has been cancelled
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		b, _ := json.Marshal(m)

		var entry SentinelOneTimelineFull
		if err := json.Unmarshal(b, &entry); err != nil {
			plugin.Logger(ctx).Error("listSentinelOneTimeline", "unmarshal_error", err)
			continue
		}

		// Stream the item into Steampipe
		d.StreamListItem(ctx, entry)

		// Stop if the query’s SQL LIMIT has been reached
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	return nil, nil
}
