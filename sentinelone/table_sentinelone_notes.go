package sentinelone

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	sdkproto "github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

type SentinelOneNoteFull struct {
	CreatedAt time.Time `json:"createdAt"`
	Creator   string    `json:"creator"`
	CreatorId string    `json:"creatorId"`
	Edited    bool      `json:"edited"`
	Id        string    `json:"id"`
	Text      string    `json:"text"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Defines the Steampipe table
func tableSentinelOneNotes(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "sentinelone_note",
		Description: "Threats Notes from SentinelOne",
		List: &plugin.ListConfig{
			Hydrate:    listSentinelOneNotes,
			KeyColumns: []*plugin.KeyColumn{{Name: "threat_id", Require: plugin.Required}},
		},
		Columns: []*plugin.Column{
			{Name: "threat_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromQual("threat_id")},
			{Name: "created_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("CreatedAt")},
			{Name: "creator", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Creator")},
			{Name: "creator_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("CreatorId")},
			{Name: "edited", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("Edited")},
			{Name: "id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Id")},
			{Name: "text", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Text")},
			{Name: "updated_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("UpdatedAt")},
		},
	}
}

// Retrieves the raw, paginated list of notes
func (c *SentinelOneClient) ListNotesRaw(ctx context.Context, d *plugin.QueryData) (
	[]interface{},
	map[string]interface{},
	[]interface{},
	error,
) {
	threatId := d.EqualsQuals["threat_id"].GetStringValue()
	if threatId == "" {
		return nil, nil, nil, fmt.Errorf("missing required field: threat_id")
	}

	endpoint := fmt.Sprintf("/web/api/v2.1/threats/%s/notes", threatId)
	return c.fetchPaginatedData(ctx, d, endpoint, 1000)
}

// Streams each note into Steampipe
func listSentinelOneNotes(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	client, err := Connect(ctx, d)
	if err != nil {
		return nil, err
	}

	rawData, _, _, err := client.ListNotesRaw(ctx, d)
	if err != nil {
		return nil, err
	}

	for _, item := range rawData {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		b, _ := json.Marshal(m)

		var note SentinelOneNoteFull
		if err := json.Unmarshal(b, &note); err != nil {
			plugin.Logger(ctx).Error("sentinelone_note", "unmarshal_error", err)
			continue
		}

		d.StreamListItem(ctx, note)

		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	return nil, nil
}
