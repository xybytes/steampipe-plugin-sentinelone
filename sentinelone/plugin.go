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
			"sentinelone_agents":       tableSentinelOneAgents(ctx),
			"sentinelone_alerts":       tableSentinelOneAlerts(ctx),
			"sentinelone_threats":      tableSentinelOneThreats(ctx),
			"sentinelone_timeline":     tableSentinelOneTimeline(ctx),
			"sentinelone_notes":        tableSentinelOneNotes(ctx),
			"sentinelone_activities":   tableSentinelOneActivities(ctx),
			"sentinelone_applications": tableSentinelOneApplications(ctx),
			"sentinelone_cves":         tableSentinelOneCVEs(ctx),
		},
	}
}
