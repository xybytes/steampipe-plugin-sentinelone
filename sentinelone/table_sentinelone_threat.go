package sentinelone

import (
	"context"
	"encoding/json"
	"time"

	sdkproto "github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

type SentinelOneThreat struct {
	ID                 string             `json:"id"`
	ThreatInfo         ThreatInfo         `json:"threatInfo"`
	AgentRealtimeInfo  AgentRealtimeInfo  `json:"agentRealtimeInfo"`
	AgentDetectionInfo AgentDetectionInfo `json:"agentDetectionInfo"`
}

type ThreatInfo struct {
	ThreatName      string    `json:"threatName"`
	ThreatId        string    `json:"threatId"`
	IdentifiedAt    time.Time `json:"identifiedAt"`
	ConfidenceLevel string    `json:"confidenceLevel"`
	IncidentStatus  string    `json:"incidentStatus"`
	PublisherName   string    `json:"publisherName"`
	ProcessUser     string    `json:"processUser"`
	Sha256          string    `json:"sha256"`
	DetectionType   string    `json:"detectionType"`
	CreatedAt       time.Time `json:"createdAt"`
}

type AgentRealtimeInfo struct {
	AgentIsActive         bool               `json:"agentIsActive"`
	ScanStartedAt         time.Time          `json:"scanStartedAt"`
	RebootRequired        bool               `json:"rebootRequired"`
	ScanStatus            string             `json:"scanStatus"`
	ScanAbortedAt         time.Time          `json:"scanAbortedAt"`
	SiteName              string             `json:"siteName"`
	AgentOsName           string             `json:"agentOsName"`
	AgentInfected         bool               `json:"agentInfected"`
	AgentDomain           string             `json:"agentDomain"`
	AgentDecommissioned   bool               `json:"agentDecommissionedAt"`
	AgentNetworkStatus    string             `json:"agentNetworkStatus"`
	AgentUuid             string             `json:"agentUuid"`
	OperationalState      string             `json:"operationalState"`
	ScanFinishedAt        time.Time          `json:"scanFinishedAt"`
	AgentMitigationMode   string             `json:"agentMitigationMode"`
	ActiveThreats         int                `json:"activeThreats"`
	AgentOsType           string             `json:"agentOsType"`
	AgentOsRevision       string             `json:"agentOsRevision"`
	GroupId               string             `json:"groupId"`
	GroupName             string             `json:"groupName"`
	AccountName           string             `json:"accountName"`
	AccountId             string             `json:"accountId"`
	AgentMachineType      string             `json:"agentMachineType"`
	AgentIsDecommissioned bool               `json:"agentIsDecommissioned"`
	AgentComputerName     string             `json:"agentComputerName"`
	SiteId                string             `json:"siteId"`
	AgentId               string             `json:"agentId"`
	NetworkInterfaces     []NetworkInterface `json:"networkInterfaces"`
}

type AgentDetectionInfo struct {
	AgentLastLoggedInUserMail string    `json:"agentLastLoggedInUserMail"`
	AgentDomain               string    `json:"agentDomain"`
	AgentUuid                 string    `json:"agentUuid"`
	AgentMitigationMode       string    `json:"agentMitigationMode"`
	AgentIpV4                 string    `json:"agentIpV4"`
	GroupId                   string    `json:"groupId"`
	AgentRegisteredAt         time.Time `json:"agentRegisteredAt"`
	AgentDetectionState       string    `json:"agentDetectionState"`
	ExternalIp                string    `json:"externalIp"`
	AgentLastLoggedInUpn      string    `json:"agentLastLoggedInUpn"`
	GroupName                 string    `json:"groupName"`
	AgentIpV6                 string    `json:"agentIpV6"`
	AgentOsRevision           string    `json:"agentOsRevision"`
	AgentOsName               string    `json:"agentOsName"`
	SiteName                  string    `json:"siteName"`
	SiteId                    string    `json:"siteId"`
	AccountName               string    `json:"accountName"`
	AssetVersion              string    `json:"assetVersion"`
	AccountId                 string    `json:"accountId"`
	AgentLastLoggedInUserName string    `json:"agentLastLoggedInUserName"`
}

type NetworkInterface struct {
	Name     string   `json:"name"`
	Inet6    []string `json:"inet6"`
	Physical string   `json:"physical"`
	Inet     []string `json:"inet"`
	ID       string   `json:"id"`
}

// Defines the Steampipe table
func tableSentinelOneThreats(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "sentinelone_threat",
		Description: "Get data of threats.",
		List:        &plugin.ListConfig{Hydrate: listSentinelOneThreats},
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
			{Name: "id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ID")},

			// ThreatInfo
			{Name: "threat_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.ThreatName"), Description: "Name of the detected threat."},
			{Name: "threat_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.ThreatId"), Description: "Unique identifier of the threat."},
			{Name: "identified_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("ThreatInfo.IdentifiedAt"), Description: "Timestamp when the threat was first identified."},
			{Name: "confidence_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.ConfidenceLevel"), Description: "Confidence level of the threat detection."},
			{Name: "incident_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.IncidentStatus"), Description: "Current status of the incident."},
			{Name: "publisher_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.PublisherName"), Description: "Name of the threat intelligence publisher."},
			{Name: "process_user", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.ProcessUser"), Description: "User context under which the threat process ran."},
			{Name: "sha256", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.Sha256"), Description: "SHA256 hash of the threat binary."},
			{Name: "detection_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.DetectionType"), Description: "Type of detection that flagged the threat."},
			{Name: "created_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("ThreatInfo.CreatedAt"), Description: "Timestamp when the threat record was created."},

			//AgentRealtimeInfo
			{Name: "agent_is_active", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("AgentRealtimeInfo.AgentIsActive"), Description: "Indicates if the agent is currently active."},
			{Name: "scan_started_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("AgentRealtimeInfo.ScanStartedAt"), Description: "Timestamp when the scan started."},
			{Name: "reboot_required", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("AgentRealtimeInfo.RebootRequired"), Description: "Indicates if a reboot is required after scan."},
			{Name: "scan_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.ScanStatus"), Description: "Current status of the realtime scan."},
			{Name: "scan_aborted_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("AgentRealtimeInfo.ScanAbortedAt"), Description: "Timestamp when the scan was aborted."},
			{Name: "site_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.SiteName"), Description: "Name of the site associated with the agent."},
			{Name: "agent_os_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentOsName"), Description: "Name of the operating system on the agent."},
			{Name: "agent_infected", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("AgentRealtimeInfo.AgentInfected"), Description: "Indicates if the agent reports an infection."},
			{Name: "agent_domain", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentDomain"), Description: "Domain of the agent machine."},
			{Name: "agent_decommissioned_at", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("AgentRealtimeInfo.AgentDecommissioned"), Description: "Indicates if the agent has been decommissioned."},
			{Name: "agent_network_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentNetworkStatus"), Description: "Current network status of the agent."},
			{Name: "agent_uuid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentUuid"), Description: "UUID of the agent instance."},
			{Name: "operational_state", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.OperationalState"), Description: "Current operational state of the agent."},
			{Name: "scan_finished_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("AgentRealtimeInfo.ScanFinishedAt"), Description: "Timestamp when the scan completed."},
			{Name: "agent_mitigation_mode", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentMitigationMode"), Description: "Current mitigation mode of the agent."},
			{Name: "active_threats", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("AgentRealtimeInfo.ActiveThreats"), Description: "Number of active threats detected in realtime."},
			{Name: "agent_os_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentOsType"), Description: "Operating system type of the agent."},
			{Name: "agent_os_revision", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentOsRevision"), Description: "Operating system revision of the agent."},
			{Name: "group_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.GroupId"), Description: "ID of the management group."},
			{Name: "group_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.GroupName"), Description: "Name of the management group."},
			{Name: "account_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AccountName"), Description: "Name of the account associated with the agent."},
			{Name: "account_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AccountId"), Description: "ID of the account associated with the agent."},
			{Name: "agent_machine_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentMachineType"), Description: "Type of machine on which the agent runs."},
			{Name: "agent_is_decommissioned", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("AgentRealtimeInfo.AgentIsDecommissioned"), Description: "Indicates if the agent is decommissioned."},
			{Name: "agent_computer_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentComputerName"), Description: "Computer name where the agent is installed."},
			{Name: "site_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.SiteId"), Description: "ID of the site associated with the agent."},
			{Name: "network_interfaces", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("AgentRealtimeInfo.NetworkInterfaces"), Description: "Network interfaces configuration of the agent."},
			{Name: "agent_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentId"), Description: "Unique identifier of the agent."},

			//AgentDetectionInfo
			{Name: "agent_last_logged_in_user_mail", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentLastLoggedInUserMail"), Description: "Email of the last user who logged in to the agent."},
			{Name: "agent_detection_domain", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentDomain"), Description: "Domain of the agent detection."},
			{Name: "agent_detection_uuid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentUuid"), Description: "UUID of the agent detection event."},
			{Name: "agent_detection_mitigation_mode", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentMitigationMode"), Description: "Mitigation mode at detection time."},
			{Name: "agent_ip_v4", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentIpV4"), Description: "IPv4 address of the agent at detection time."},
			{Name: "agent_registered_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("AgentDetectionInfo.AgentRegisteredAt"), Description: "Timestamp when the agent was registered."},
			{Name: "agent_detection_state", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentDetectionState"), Description: "Current detection state of the agent."},
			{Name: "external_ip_detection", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.ExternalIp"), Description: "External IP captured at detection."},
			{Name: "agent_last_logged_in_upn", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentLastLoggedInUpn"), Description: "UPN of the last user who logged in."},
			{Name: "detection_group_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.GroupName"), Description: "Group name at detection."},
			{Name: "agent_ip_v6", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentIpV6"), Description: "IPv6 address of the agent at detection time."},
			{Name: "detection_os_revision", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentOsRevision"), Description: "OS revision at detection."},
			{Name: "detection_os_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentOsName"), Description: "OS name at detection."},
			{Name: "detection_site_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.SiteName"), Description: "Site name at detection."},
			{Name: "detection_site_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.SiteId"), Description: "Site ID at detection."},
			{Name: "detection_account_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AccountName"), Description: "Account name at detection."},
			{Name: "detection_account_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AccountId"), Description: "Account ID at detection."},
			{Name: "agent_last_logged_in_user_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentLastLoggedInUserName"), Description: "Name of the last user who logged into the agent."},
		},
	}
}

// retrieves paginated threat data
func (t *SentinelOneClient) ListThreatsRaw(ctx context.Context, d *plugin.QueryData) (
	[]interface{},
	map[string]interface{},
	[]interface{},
	error,
) {
	// passing in: the request context, the query data (for SQL LIMIT), the API endpoint, the maximum page size per HTTP call
	return t.fetchPaginatedData(ctx, d, "/web/api/v2.1/threats", 1000)
}

// Stream each threat into Steampipe, respecting context cancellation and SQL LIMIT.
func listSentinelOneThreats(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	// Establish the API client
	client, err := Connect(ctx, d)
	if err != nil {
		return nil, err
	}

	// Fetch rawData
	rawData, _, _, err := client.ListThreatsRaw(ctx, d)
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

		var threat SentinelOneThreat
		if err := json.Unmarshal(b, &threat); err != nil {
			plugin.Logger(ctx).Error("listSentinelOneThreats", "unmarshal_error", err)
			continue
		}

		// Stream the item into Steampipe
		d.StreamListItem(ctx, threat)

		// Stop if the query’s SQL LIMIT has been reached
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	return nil, nil
}
