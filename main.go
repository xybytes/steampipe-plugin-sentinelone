package main

import (
	"github.com/xybytes/steampipe-plugin-sentinelone/sentinelone"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		PluginFunc: sentinelone.Plugin,
	})
}
