package sentinelone

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func Plugin(ctx context.Context) *plugin.Plugin {
	return &plugin.Plugin{
		Name:             "steampipe-plugin-sentinelone",
		DefaultTransform: transform.FromGo(),
		ConnectionConfigSchema: &plugin.ConnectionConfigSchema{
			NewInstance: ConfigInstance,
		},
		TableMap: map[string]*plugin.Table{
			"sentinelone_agent":       tableSentinelOneAgents(ctx),
			"sentinelone_alert":       tableSentinelOneAlerts(ctx),
			"sentinelone_threat":      tableSentinelOneThreats(ctx),
			"sentinelone_timeline":    tableSentinelOneTimeline(ctx),
			"sentinelone_note":        tableSentinelOneNotes(ctx),
			"sentinelone_activity":    tableSentinelOneActivities(ctx),
			"sentinelone_application": tableSentinelOneApplications(ctx),
			"sentinelone_cve":         tableSentinelOneCVEs(ctx),
		},
	}
}
