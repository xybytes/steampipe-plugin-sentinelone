package sentinelone

import (
	"context"
	"encoding/json"
	"time"

	sdkproto "github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	plugin "github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

type SentinelOneAgentFull struct {
	AccountID                      string                 `json:"accountId"`
	AccountName                    string                 `json:"accountName"`
	ActiveDirectory                map[string]interface{} `json:"activeDirectory"`
	ActiveProtection               []interface{}          `json:"activeProtection"`
	ActiveThreats                  int                    `json:"activeThreats"`
	AgentVersion                   string                 `json:"agentVersion"`
	AllowRemoteShell               bool                   `json:"allowRemoteShell"`
	AppsVulnerabilityStatus        string                 `json:"appsVulnerabilityStatus"`
	CloudProviders                 map[string]interface{} `json:"cloudProviders"`
	ComputerName                   string                 `json:"computerName"`
	ConsoleMigrationStatus         string                 `json:"consoleMigrationStatus"`
	ContainerizedWorkloadCounts    map[string]interface{} `json:"containerizedWorkloadCounts"`
	CoreCount                      int                    `json:"coreCount"`
	CPUCount                       int                    `json:"cpuCount"`
	CPUID                          string                 `json:"cpuId"`
	CreatedAt                      time.Time              `json:"createdAt"`
	DetectionState                 string                 `json:"detectionState"`
	Domain                         string                 `json:"domain"`
	EncryptedApplications          bool                   `json:"encryptedApplications"`
	ExternalID                     string                 `json:"externalId"`
	ExternalIP                     string                 `json:"externalIp"`
	FirewallEnabled                bool                   `json:"firewallEnabled"`
	FirstFullModeTime              time.Time              `json:"firstFullModeTime"`
	FullDiskScanLastUpdatedAt      time.Time              `json:"fullDiskScanLastUpdatedAt"`
	GroupID                        string                 `json:"groupId"`
	GroupIP                        string                 `json:"groupIp"`
	GroupName                      string                 `json:"groupName"`
	HasContainerizedWorkload       bool                   `json:"hasContainerizedWorkload"`
	ID                             string                 `json:"id"`
	InRemoteShellSession           bool                   `json:"inRemoteShellSession"`
	Infected                       bool                   `json:"infected"`
	InstallerType                  string                 `json:"installerType"`
	IsActive                       bool                   `json:"isActive"`
	IsAdConnector                  bool                   `json:"isAdConnector"`
	IsDecommissioned               bool                   `json:"isDecommissioned"`
	IsHyperAutomate                bool                   `json:"isHyperAutomate"`
	IsPendingUninstall             bool                   `json:"isPendingUninstall"`
	IsUninstalled                  bool                   `json:"isUninstalled"`
	IsUpToDate                     bool                   `json:"isUpToDate"`
	LastSeen                       time.Time              `json:"lastSeen"`
	LastActiveDate                 time.Time              `json:"lastActiveDate"`
	LastIPToMgmt                   string                 `json:"lastIpToMgmt"`
	LastLoggedInUserName           string                 `json:"lastLoggedInUserName"`
	LastSuccessfulScanDate         time.Time              `json:"lastSuccessfulScanDate"`
	LicenseKey                     string                 `json:"licenseKey"`
	LocationEnabled                bool                   `json:"locationEnabled"`
	LocationType                   string                 `json:"locationType"`
	Locations                      []interface{}          `json:"locations"`
	MachineSID                     string                 `json:"machineSid"`
	MachineType                    string                 `json:"machineType"`
	MissingPermissions             []interface{}          `json:"missingPermissions"`
	MitigationMode                 string                 `json:"mitigationMode"`
	MitigationModeSuspicious       string                 `json:"mitigationModeSuspicious"`
	ModelName                      string                 `json:"modelName"`
	NetworkInterfaces              []interface{}          `json:"networkInterfaces"`
	NetworkQuarantineEnabled       bool                   `json:"networkQuarantineEnabled"`
	NetworkStatus                  string                 `json:"networkStatus"`
	OperationalState               string                 `json:"operationalState"`
	OperationalStateExpiration     time.Time              `json:"operationalStateExpiration"`
	OSArch                         string                 `json:"osArch"`
	OSName                         string                 `json:"osName"`
	OSRevision                     string                 `json:"osRevision"`
	OSStartTime                    time.Time              `json:"osStartTime"`
	OSType                         string                 `json:"osType"`
	OSUsername                     string                 `json:"osUsername"`
	ProxyStates                    map[string]interface{} `json:"proxyStates"`
	RangerStatus                   string                 `json:"rangerStatus"`
	RangerVersion                  string                 `json:"rangerVersion"`
	RegisteredAt                   time.Time              `json:"registeredAt"`
	RemoteProfilingState           string                 `json:"remoteProfilingState"`
	RemoteProfilingStateExpiration time.Time              `json:"remoteProfilingStateExpiration"`
	ScanAbortedAt                  time.Time              `json:"scanAbortedAt"`
	ScanFinishedAt                 time.Time              `json:"scanFinishedAt"`
	ScanStartedAt                  time.Time              `json:"scanStartedAt"`
	ScanStatus                     string                 `json:"scanStatus"`
	SerialNumber                   string                 `json:"serialNumber"`
	ShowAlertIcon                  bool                   `json:"showAlertIcon"`
	SiteID                         string                 `json:"siteId"`
	SiteName                       string                 `json:"siteName"`
	StorageName                    string                 `json:"storageName"`
	StorageType                    string                 `json:"storageType"`
	Tags                           map[string]interface{} `json:"tags"`
	ThreatRebootRequired           bool                   `json:"threatRebootRequired"`
	TotalMemory                    int                    `json:"totalMemory"`
	UpdatedAt                      time.Time              `json:"updatedAt"`
	UserActionsNeeded              []interface{}          `json:"userActionsNeeded"`
	UUID                           string                 `json:"uuid"`
}

// tableSentinelOneAgents Steampipe Table.
func tableSentinelOneAgents(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "sentinelone_agents",
		Description: "Get the Agents and their data",
		List:        &plugin.ListConfig{Hydrate: listSentinelOneAgents},
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
			{Name: "account_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AccountID")},
			{Name: "account_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AccountName")},
			{Name: "active_directory", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("ActiveDirectory")},
			{Name: "active_protection", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("ActiveProtection")},
			{Name: "active_threats", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("ActiveThreats")},
			{Name: "agent_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentVersion")},
			{Name: "allow_remote_shell", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("AllowRemoteShell")},
			{Name: "apps_vulnerability_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AppsVulnerabilityStatus")},
			{Name: "cloud_providers", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("CloudProviders")},
			{Name: "computer_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ComputerName")},
			{Name: "console_migration_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ConsoleMigrationStatus")},
			{Name: "containerized_workload_counts", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("ContainerizedWorkloadCounts")},
			{Name: "core_count", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("CoreCount")},
			{Name: "cpu_count", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("CPUCount")},
			{Name: "cpu_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("CPUID")},
			{Name: "created_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("CreatedAt")},
			{Name: "detection_state", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("DetectionState")},
			{Name: "domain", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Domain")},
			{Name: "encrypted_applications", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("EncryptedApplications")},
			{Name: "external_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ExternalID")},
			{Name: "external_ip", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ExternalIP")},
			{Name: "firewall_enabled", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("FirewallEnabled")},
			{Name: "first_full_mode_time", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("FirstFullModeTime")},
			{Name: "full_disk_scan_last_updated_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("FullDiskScanLastUpdatedAt")},
			{Name: "group_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("GroupID")},
			{Name: "group_ip", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("GroupIP")},
			{Name: "group_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("GroupName")},
			{Name: "has_containerized_workload", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("HasContainerizedWorkload")},
			{Name: "id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ID")},
			{Name: "in_remote_shell_session", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("InRemoteShellSession")},
			{Name: "infected", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("Infected")},
			{Name: "installer_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("InstallerType")},
			{Name: "is_active", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("IsActive")},
			{Name: "is_ad_connector", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("IsAdConnector")},
			{Name: "is_decommissioned", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("IsDecommissioned")},
			{Name: "is_hyper_automate", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("IsHyperAutomate")},
			{Name: "is_pending_uninstall", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("IsPendingUninstall")},
			{Name: "is_uninstalled", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("IsUninstalled")},
			{Name: "is_up_to_date", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("IsUpToDate")},
			{Name: "last_active_date", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("LastActiveDate")},
			{Name: "last_ip_to_mgmt", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("LastIPToMgmt")},
			{Name: "last_logged_in_user_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("LastLoggedInUserName")},
			{Name: "last_successful_scan_date", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("LastSuccessfulScanDate")},
			{Name: "license_key", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("LicenseKey")},
			{Name: "location_enabled", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("LocationEnabled")},
			{Name: "location_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("LocationType")},
			{Name: "locations", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("Locations")},
			{Name: "machine_sid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("MachineSID")},
			{Name: "machine_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("MachineType")},
			{Name: "missing_permissions", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("MissingPermissions")},
			{Name: "mitigation_mode", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("MitigationMode")},
			{Name: "mitigation_mode_suspicious", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("MitigationModeSuspicious")},
			{Name: "model_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ModelName")},
			{Name: "network_interfaces", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("NetworkInterfaces")},
			{Name: "network_quarantine_enabled", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("NetworkQuarantineEnabled")},
			{Name: "network_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("NetworkStatus")},
			{Name: "operational_state", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OperationalState")},
			{Name: "operational_state_expiration", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("OperationalStateExpiration")},
			{Name: "os_arch", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OSArch")},
			{Name: "os_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OSName")},
			{Name: "os_revision", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OSRevision")},
			{Name: "os_start_time", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("OSStartTime")},
			{Name: "os_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OSType")},
			{Name: "os_username", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OSUsername")},
			{Name: "proxy_states", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("ProxyStates")},
			{Name: "ranger_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RangerStatus")},
			{Name: "ranger_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RangerVersion")},
			{Name: "registered_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("RegisteredAt")},
			{Name: "remote_profiling_state", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RemoteProfilingState")},
			{Name: "remote_profiling_state_expiration", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("RemoteProfilingStateExpiration")},
			{Name: "scan_aborted_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("ScanAbortedAt")},
			{Name: "scan_finished_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("ScanFinishedAt")},
			{Name: "scan_started_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("ScanStartedAt")},
			{Name: "scan_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ScanStatus")},
			{Name: "serial_number", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SerialNumber")},
			{Name: "show_alert_icon", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("ShowAlertIcon")},
			{Name: "site_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SiteID")},
			{Name: "site_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SiteName")},
			{Name: "storage_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("StorageName")},
			{Name: "storage_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("StorageType")},
			{Name: "tags", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("Tags")},
			{Name: "threat_reboot_required", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("ThreatRebootRequired")},
			{Name: "total_memory", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("TotalMemory")},
			{Name: "updated_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("UpdatedAt")},
			{Name: "user_actions_needed", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("UserActionsNeeded")},
			{Name: "uuid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("UUID")},
		},
	}
}

// ListThreatsRaw retrieves paginated threat data
func (t *SentinelOneClient) ListAgentsRaw(ctx context.Context, d *plugin.QueryData) (
	[]interface{},
	map[string]interface{},
	[]interface{},
	error,
) {
	// passing in: the request context, the query data (for SQL LIMIT), the API endpoint, the maximum page size per HTTP call
	return t.fetchPaginatedData(ctx, d, "/web/api/v2.1/agents", 1000)
}

// Stream each agent into Steampipe, stopping at SQL LIMIT, context cancellation, or when no more data.
func listSentinelOneAgents(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	// Establish the API client
	client, err := Connect(ctx, d)
	if err != nil {
		return nil, err
	}

	// Fetch rawData
	rawData, _, _, err := client.ListAgentsRaw(ctx, d)
	if err != nil {
		return nil, err
	}

	// Iterate over each raw item
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

		var agent SentinelOneAgentFull
		if err := json.Unmarshal(b, &agent); err != nil {
			plugin.Logger(ctx).Error("listSentinelOneAgents", "unmarshal_error", err)
			continue
		}

		// Stream the item into Steampipe
		d.StreamListItem(ctx, agent)

		// Stop if the query’s SQL LIMIT has been reached
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	return nil, nil
}
