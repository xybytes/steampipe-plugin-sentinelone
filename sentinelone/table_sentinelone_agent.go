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
		Name:        "sentinelone_agent",
		Description: "Get the Agents and their data.",
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
			{Name: "account_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AccountID"), Description: "Agent Account ID"},
			{Name: "account_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AccountName"), Description: "The name associated with the SentinelOne account."},
			{Name: "active_directory", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("ActiveDirectory"), Description: "Active Directory configurations for the computer."},
			{Name: "active_protection", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("ActiveProtection"), Description: "Details and status of active protection."},
			{Name: "active_threats", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("ActiveThreats"), Description: "Number of active threats detected."},
			{Name: "agent_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentVersion"), Description: "Version of the installed SentinelOne agent."},
			{Name: "allow_remote_shell", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("AllowRemoteShell"), Description: "Indicates if remote shell access is allowed."},
			{Name: "apps_vulnerability_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AppsVulnerabilityStatus"), Description: "Vulnerability status of installed applications."},
			{Name: "cloud_providers", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("CloudProviders"), Description: "List of cloud providers associated with the computer."},
			{Name: "computer_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ComputerName"), Description: "Hostname of the managed computer."},
			{Name: "console_migration_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ConsoleMigrationStatus"), Description: "Status of console migration."},
			{Name: "containerized_workload_counts", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("ContainerizedWorkloadCounts"), Description: "Counts of containerized workloads."},
			{Name: "core_count", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("CoreCount"), Description: "Number of CPU cores available."},
			{Name: "cpu_count", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("CPUCount"), Description: "Total number of logical processors."},
			{Name: "cpu_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("CPUID"), Description: "Unique identifier of the CPU."},
			{Name: "created_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("CreatedAt"), Description: "Timestamp when the computer was registered."},
			{Name: "detection_state", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("DetectionState"), Description: "Current threat detection state."},
			{Name: "domain", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Domain"), Description: "Active Directory domain of the computer."},
			{Name: "encrypted_applications", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("EncryptedApplications"), Description: "Indicates if applications are encrypted."},
			{Name: "external_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ExternalID"), Description: "External identifier of the computer."},
			{Name: "external_ip", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ExternalIP"), Description: "External IP address of the computer."},
			{Name: "firewall_enabled", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("FirewallEnabled"), Description: "Indicates if the firewall is enabled."},
			{Name: "first_full_mode_time", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("FirstFullModeTime"), Description: "Timestamp of the first full scan executed."},
			{Name: "full_disk_scan_last_updated_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("FullDiskScanLastUpdatedAt"), Description: "Timestamp of the last full disk scan update."},
			{Name: "group_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("GroupID"), Description: "ID of the management group."},
			{Name: "group_ip", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("GroupIP"), Description: "IP address of the management group."},
			{Name: "group_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("GroupName"), Description: "Name of the management group."},
			{Name: "has_containerized_workload", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("HasContainerizedWorkload"), Description: "Indicates if containerized workloads are present."},
			{Name: "id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ID"), Description: "Unique identifier of the computer record."},
			{Name: "in_remote_shell_session", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("InRemoteShellSession"), Description: "Indicates if a remote shell session is active."},
			{Name: "infected", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("Infected"), Description: "Indicates if the computer is infected."},
			{Name: "installer_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("InstallerType"), Description: "Type of installer used."},
			{Name: "is_active", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("IsActive"), Description: "Indicates if the computer is active in the system."},
			{Name: "is_ad_connector", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("IsAdConnector"), Description: "Indicates if it functions as an AD connector."},
			{Name: "is_decommissioned", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("IsDecommissioned"), Description: "Indicates if the computer is decommissioned."},
			{Name: "is_hyper_automate", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("IsHyperAutomate"), Description: "Indicates if Hyper Automate is in use."},
			{Name: "is_pending_uninstall", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("IsPendingUninstall"), Description: "Indicates if uninstallation is pending."},
			{Name: "is_uninstalled", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("IsUninstalled"), Description: "Indicates if the agent has been uninstalled."},
			{Name: "is_up_to_date", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("IsUpToDate"), Description: "Indicates if the agent is up to date."},
			{Name: "last_active_date", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("LastActiveDate"), Description: "Last recorded active date."},
			{Name: "last_ip_to_mgmt", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("LastIPToMgmt"), Description: "Last IP used for management."},
			{Name: "last_logged_in_user_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("LastLoggedInUserName"), Description: "Name of the last logged-in user."},
			{Name: "last_successful_scan_date", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("LastSuccessfulScanDate"), Description: "Timestamp of the last successful scan."},
			{Name: "license_key", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("LicenseKey"), Description: "Associated license key."},
			{Name: "location_enabled", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("LocationEnabled"), Description: "Indicates if location tracking is enabled."},
			{Name: "location_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("LocationType"), Description: "Type of device location."},
			{Name: "locations", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("Locations"), Description: "List of recorded locations."},
			{Name: "machine_sid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("MachineSID"), Description: "Unique machine SID."},
			{Name: "machine_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("MachineType"), Description: "Type of machine (e.g. server, workstation)."},
			{Name: "missing_permissions", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("MissingPermissions"), Description: "Permissions missing on the device."},
			{Name: "mitigation_mode", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("MitigationMode"), Description: "Active mitigation mode."},
			{Name: "mitigation_mode_suspicious", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("MitigationModeSuspicious"), Description: "Mitigation mode for suspicious behavior."},
			{Name: "model_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ModelName"), Description: "Hardware model name."},
			{Name: "network_interfaces", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("NetworkInterfaces"), Description: "Details of network interfaces."},
			{Name: "network_quarantine_enabled", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("NetworkQuarantineEnabled"), Description: "Indicates if network quarantine is enabled."},
			{Name: "network_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("NetworkStatus"), Description: "Current network connectivity status."},
			{Name: "operational_state", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OperationalState"), Description: "Current operational state."},
			{Name: "operational_state_expiration", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("OperationalStateExpiration"), Description: "Expiration timestamp of the operational state."},
			{Name: "os_arch", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OSArch"), Description: "Operating system architecture."},
			{Name: "os_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OSName"), Description: "Operating system name."},
			{Name: "os_revision", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OSRevision"), Description: "OS revision or version."},
			{Name: "os_start_time", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("OSStartTime"), Description: "Timestamp of last OS start."},
			{Name: "os_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OSType"), Description: "Type of operating system (e.g. Windows, Linux)."},
			{Name: "os_username", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OSUsername"), Description: "Currently logged-in OS user."},
			{Name: "proxy_states", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("ProxyStates"), Description: "Configured proxy states."},
			{Name: "ranger_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RangerStatus"), Description: "Status of the Ranger component."},
			{Name: "ranger_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RangerVersion"), Description: "Version of the Ranger component."},
			{Name: "registered_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("RegisteredAt"), Description: "Registration timestamp in SentinelOne."},
			{Name: "remote_profiling_state", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RemoteProfilingState"), Description: "Remote Profile State"},
			{Name: "remote_profiling_state_expiration", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("RemoteProfilingStateExpiration"), Description: "Expiration timestamp of remote profiling state."},
			{Name: "scan_aborted_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("ScanAbortedAt"), Description: "Timestamp when the scan was aborted."},
			{Name: "scan_finished_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("ScanFinishedAt")},
			{Name: "scan_started_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("ScanStartedAt")},
			{Name: "scan_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ScanStatus"), Description: "Current scan status."},
			{Name: "serial_number", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SerialNumber"), Description: "Device serial number."},
			{Name: "show_alert_icon", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("ShowAlertIcon"), Description: "Indicates if the alert icon should be shown."},
			{Name: "site_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SiteID"), Description: "ID of the site the computer belongs to."},
			{Name: "site_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SiteName"), Description: "Name of the site the computer belongs to."},
			{Name: "storage_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("StorageName"), Description: "Name of the storage volume."},
			{Name: "storage_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("StorageType"), Description: "Type of storage (e.g. HDD, SSD)."},
			{Name: "tags", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("Tags"), Description: "List of tags associated with the computer."},
			{Name: "threat_reboot_required", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("ThreatRebootRequired"), Description: "Indicates if a reboot is required after threat mitigation."},
			{Name: "total_memory", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("TotalMemory"), Description: "Total memory (in MB) of the device."},
			{Name: "updated_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("UpdatedAt"), Description: "Timestamp of the last record update."},
			{Name: "user_actions_needed", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("UserActionsNeeded"), Description: "Actions required by the user to resolve issues."},
			{Name: "uuid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("UUID"), Description: "Unique device UUID."},
		},
	}
}

// retrieves paginated threat data
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
