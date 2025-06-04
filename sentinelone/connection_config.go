package sentinelone

import (
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

type sentineloneConfig struct {
	ClientID  *string `hcl:"client_id"`
	AuthToken *string `hcl:"auth_token"`
}

func ConfigInstance() interface{} {
	return &sentineloneConfig{}
}

// GetConfig :: retrieve and cast connection config from query data
func GetConfig(connection *plugin.Connection) sentineloneConfig {
	if connection == nil || connection.Config == nil {
		return sentineloneConfig{}
	}
	// connection.Config è di tipo sentineloneConfig (non *sentineloneConfig)
	cfg, ok := connection.Config.(sentineloneConfig)
	if !ok {
		return sentineloneConfig{}
	}
	return cfg
}
