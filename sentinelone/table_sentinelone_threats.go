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
	MitigationStatus   []MitigationStatus `json:"mitigationStatus"`
}

type ThreatInfo struct {
	ThreatName      string    `json:"threatName"`
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
	AgentIsActive         bool          `json:"agentIsActive"`
	ScanStartedAt         time.Time     `json:"scanStartedAt"`
	RebootRequired        bool          `json:"rebootRequired"`
	ScanStatus            string        `json:"scanStatus"`
	ScanAbortedAt         time.Time     `json:"scanAbortedAt"`
	SiteName              string        `json:"siteName"`
	AgentOsName           string        `json:"agentOsName"`
	AgentInfected         bool          `json:"agentInfected"`
	AgentDomain           string        `json:"agentDomain"`
	AgentDecommissioned   bool          `json:"agentDecommissionedAt"`
	AgentNetworkStatus    string        `json:"agentNetworkStatus"`
	AgentUuid             string        `json:"agentUuid"`
	OperationalState      string        `json:"operationalState"`
	ScanFinishedAt        time.Time     `json:"scanFinishedAt"`
	AgentMitigationMode   string        `json:"agentMitigationMode"`
	ActiveThreats         int           `json:"activeThreats"`
	AgentOsType           string        `json:"agentOsType"`
	AgentOsRevision       string        `json:"agentOsRevision"`
	GroupId               string        `json:"groupId"`
	GroupName             string        `json:"groupName"`
	AgentVersion          string        `json:"agentVersion"`
	StorageName           string        `json:"storageName"`
	AccountName           string        `json:"accountName"`
	AccountId             string        `json:"accountId"`
	AgentMachineType      string        `json:"agentMachineType"`
	AgentIsDecommissioned bool          `json:"agentIsDecommissioned"`
	AgentComputerName     string        `json:"agentComputerName"`
	SiteId                string        `json:"siteId"`
	UserActionsNeeded     []interface{} `json:"userActionsNeeded"`
	NetworkInterfaces     []interface{} `json:"networkInterfaces"`
	AgentId               string        `json:"agentId"`
	StorageType           string        `json:"storageType"`
}

type AgentDetectionInfo struct {
	AgentLastLoggedInUserMail string      `json:"agentLastLoggedInUserMail"`
	AgentVersion              string      `json:"agentVersion"`
	AgentDomain               string      `json:"agentDomain"`
	AgentUuid                 string      `json:"agentUuid"`
	AgentMitigationMode       string      `json:"agentMitigationMode"`
	AgentIpV4                 string      `json:"agentIpV4"`
	GroupId                   string      `json:"groupId"`
	AgentRegisteredAt         time.Time   `json:"agentRegisteredAt"`
	AgentDetectionState       string      `json:"agentDetectionState"`
	ExternalIp                string      `json:"externalIp"`
	AgentLastLoggedInUpn      string      `json:"agentLastLoggedInUpn"`
	GroupName                 string      `json:"groupName"`
	AgentIpV6                 string      `json:"agentIpV6"`
	AgentOsRevision           string      `json:"agentOsRevision"`
	AgentOsName               string      `json:"agentOsName"`
	SiteName                  string      `json:"siteName"`
	SiteId                    string      `json:"siteId"`
	AccountName               string      `json:"accountName"`
	AssetVersion              string      `json:"assetVersion"`
	AccountId                 string      `json:"accountId"`
	AgentLastLoggedInUserName string      `json:"agentLastLoggedInUserName"`
	CloudProviders            interface{} `json:"cloudProviders"`

	// Alerts Fields
	OSFamily    string `json:"osFamily"`
	OSName      string `json:"osName"`
	Name        string `json:"name"`
	OSRevision  string `json:"osRevision"`
	UUID        string `json:"uuid"`
	MachineType string `json:"machineType"`
	Version     string `json:"version"`
}

type MitigationStatus struct {
	Status            string    `json:"status"`
	Action            string    `json:"action"`
	ReportId          string    `json:"reportId"`
	MitigationStarted time.Time `json:"mitigationStartedAt"`
	MitigationEnded   time.Time `json:"mitigationEndedAt"`
	AgentSupports     bool      `json:"agentSupportsReport"`
	GroupNotFound     bool      `json:"groupNotFound"`
	LatestReport      string    `json:"latestReport"`
	LastUpdate        time.Time `json:"lastUpdate"`
	ActionsCounters   struct {
		Total         int `json:"total"`
		Success       int `json:"success"`
		Failed        int `json:"failed"`
		PendingReboot int `json:"pendingReboot"`
		NotFound      int `json:"notFound"`
	} `json:"actionsCounters"`
}

type NetworkInterface struct {
	Name     string   `json:"name"`
	Inet6    []string `json:"inet6"`
	Physical string   `json:"physical"`
	Inet     []string `json:"inet"`
	ID       string   `json:"id"`
}

func tableSentinelOneThreats(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "sentinelone_threat",
		Description: "Threats from SentinelOne.",
		List: &plugin.ListConfig{
			Hydrate: listSentinelOneThreats,
		},
		Columns: []*plugin.Column{
			{Name: "id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ID")},

			// ThreatInfo
			{Name: "threat_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.ThreatName")},
			{Name: "identified_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("ThreatInfo.IdentifiedAt")},
			{Name: "confidence_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.ConfidenceLevel")},
			{Name: "incident_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.IncidentStatus")},
			{Name: "publisher_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.PublisherName")},
			{Name: "process_user", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.ProcessUser")},
			{Name: "sha256", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.Sha256")},
			{Name: "detection_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatInfo.DetectionType")},
			{Name: "created_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("ThreatInfo.CreatedAt")},

			//AgentRealtimeInfo
			{Name: "agent_is_active", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("AgentRealtimeInfo.AgentIsActive")},
			{Name: "scan_started_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("AgentRealtimeInfo.ScanStartedAt")},
			{Name: "reboot_required", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("AgentRealtimeInfo.RebootRequired")},
			{Name: "scan_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.ScanStatus")},
			{Name: "scan_aborted_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("AgentRealtimeInfo.ScanAbortedAt")},
			{Name: "site_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.SiteName")},
			{Name: "agent_os_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentOsName")},
			{Name: "agent_infected", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("AgentRealtimeInfo.AgentInfected")},
			{Name: "agent_domain", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentDomain")},
			{Name: "agent_decommissioned_at", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("AgentRealtimeInfo.AgentDecommissioned")},
			{Name: "agent_network_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentNetworkStatus")},
			{Name: "agent_uuid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentUuid")},
			{Name: "operational_state", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.OperationalState")},
			{Name: "scan_finished_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("AgentRealtimeInfo.ScanFinishedAt")},
			{Name: "agent_mitigation_mode", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentMitigationMode")},
			{Name: "active_threats", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("AgentRealtimeInfo.ActiveThreats")},
			{Name: "agent_os_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentOsType")},
			{Name: "agent_os_revision", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentOsRevision")},
			{Name: "group_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.GroupId")},
			{Name: "group_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.GroupName")},
			{Name: "agent_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentVersion")},
			{Name: "storage_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.StorageName")},
			{Name: "account_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AccountName")},
			{Name: "account_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AccountId")},
			{Name: "agent_machine_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentMachineType")},
			{Name: "agent_is_decommissioned", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("AgentRealtimeInfo.AgentIsDecommissioned")},
			{Name: "agent_computer_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentComputerName")},
			{Name: "site_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.SiteId")},
			{Name: "user_actions_needed", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("AgentRealtimeInfo.UserActionsNeeded")},
			{Name: "network_interfaces", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("AgentRealtimeInfo.NetworkInterfaces")},
			{Name: "agent_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.AgentId")},
			{Name: "storage_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentRealtimeInfo.StorageType")},

			//AgentDetectionInfo
			{Name: "agent_last_logged_in_user_mail", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentLastLoggedInUserMail")},
			{Name: "agent_detection_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentVersion")},
			{Name: "agent_detection_domain", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentDomain")},
			{Name: "agent_detection_uuid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentUuid")},
			{Name: "agent_detection_mitigation_mode", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentMitigationMode")},
			{Name: "agent_ip_v4", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentIpV4")},
			{Name: "agent_registered_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("AgentDetectionInfo.AgentRegisteredAt")},
			{Name: "agent_detection_state", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentDetectionState")},
			{Name: "external_ip_detection", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.ExternalIp")},
			{Name: "agent_last_logged_in_upn", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentLastLoggedInUpn")},
			{Name: "detection_group_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.GroupName")},
			{Name: "agent_ip_v6", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentIpV6")},
			{Name: "detection_os_revision", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentOsRevision")},
			{Name: "detection_os_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentOsName")},
			{Name: "detection_site_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.SiteName")},
			{Name: "detection_site_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.SiteId")},
			{Name: "detection_account_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AccountName")},
			{Name: "detection_account_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AccountId")},
			{Name: "agent_last_logged_in_user_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.AgentLastLoggedInUserName")},
			{Name: "cloud_providers", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("AgentDetectionInfo.CloudProviders")},

			//networkInterfaces
			{Name: "network_interfaces", Type: sdkproto.ColumnType_JSON, Transform: transform.FromField("AgentRealtimeInfo.NetworkInterfaces")},

			// mitigation
			{
				Name: "mitigation_status_status",
				Type: sdkproto.ColumnType_STRING,
				Transform: transform.FromField("MitigationStatus").Transform(
					func(_ context.Context, d *transform.TransformData) (interface{}, error) {
						if list, ok := d.Value.([]MitigationStatus); ok && len(list) > 0 {
							return list[0].Status, nil
						}
						return nil, nil
					},
				),
			},

			{Name: "mitigation_status_agent_supports",
				Type: sdkproto.ColumnType_BOOL,
				Transform: transform.FromField("MitigationStatus").Transform(func(_ context.Context, d *transform.TransformData) (interface{}, error) {
					if list, ok := d.Value.([]MitigationStatus); ok && len(list) > 0 {
						return list[0].AgentSupports, nil
					}
					return nil, nil
				}),
			},

			{Name: "mitigation_status_group_not_found",
				Type: sdkproto.ColumnType_BOOL,
				Transform: transform.FromField("MitigationStatus").Transform(func(_ context.Context, d *transform.TransformData) (interface{}, error) {
					if list, ok := d.Value.([]MitigationStatus); ok && len(list) > 0 {
						return list[0].GroupNotFound, nil
					}
					return nil, nil
				}),
			},
			{Name: "mitigation_status_latest_report",
				Type: sdkproto.ColumnType_STRING,
				Transform: transform.FromField("MitigationStatus").Transform(func(_ context.Context, d *transform.TransformData) (interface{}, error) {
					if list, ok := d.Value.([]MitigationStatus); ok && len(list) > 0 {
						return list[0].LatestReport, nil
					}
					return nil, nil
				}),
			},
			{Name: "mitigation_status_last_update",
				Type: sdkproto.ColumnType_TIMESTAMP,
				Transform: transform.FromField("MitigationStatus").Transform(func(_ context.Context, d *transform.TransformData) (interface{}, error) {
					if list, ok := d.Value.([]MitigationStatus); ok && len(list) > 0 {
						return list[0].LastUpdate, nil
					}
					return nil, nil
				}),
			},

			{Name: "mitigation_actions_total",
				Type: sdkproto.ColumnType_INT,
				Transform: transform.FromField("MitigationStatus").Transform(func(_ context.Context, d *transform.TransformData) (interface{}, error) {
					if list, ok := d.Value.([]MitigationStatus); ok && len(list) > 0 {
						return list[0].ActionsCounters.Total, nil
					}
					return nil, nil
				}),
			},
			{Name: "mitigation_actions_success",
				Type: sdkproto.ColumnType_INT,
				Transform: transform.FromField("MitigationStatus").Transform(func(_ context.Context, d *transform.TransformData) (interface{}, error) {
					if list, ok := d.Value.([]MitigationStatus); ok && len(list) > 0 {
						return list[0].ActionsCounters.Success, nil
					}
					return nil, nil
				}),
			},
			{Name: "mitigation_actions_failed",
				Type: sdkproto.ColumnType_INT,
				Transform: transform.FromField("MitigationStatus").Transform(func(_ context.Context, d *transform.TransformData) (interface{}, error) {
					if list, ok := d.Value.([]MitigationStatus); ok && len(list) > 0 {
						return list[0].ActionsCounters.Failed, nil
					}
					return nil, nil
				}),
			},
			{Name: "mitigation_actions_pending_reboot",
				Type: sdkproto.ColumnType_INT,
				Transform: transform.FromField("MitigationStatus").Transform(func(_ context.Context, d *transform.TransformData) (interface{}, error) {
					if list, ok := d.Value.([]MitigationStatus); ok && len(list) > 0 {
						return list[0].ActionsCounters.PendingReboot, nil
					}
					return nil, nil
				}),
			},
			{Name: "mitigation_actions_not_found",
				Type: sdkproto.ColumnType_INT,
				Transform: transform.FromField("MitigationStatus").Transform(func(_ context.Context, d *transform.TransformData) (interface{}, error) {
					if list, ok := d.Value.([]MitigationStatus); ok && len(list) > 0 {
						return list[0].ActionsCounters.NotFound, nil
					}
					return nil, nil
				}),
			},
		},
	}
}

// ListThreatsRaw retrieves paginated threat data
func (t *SentinelOneClient) ListThreatsRaw(ctx context.Context, d *plugin.QueryData) (
	[]interface{},
	map[string]interface{},
	[]interface{},
	error,
) {
	// passing in: the request context, the query data (for SQL LIMIT), the API endpoint, the maximum page size per HTTP call
	return t.fetchPaginatedData(ctx, d, "/web/api/v2.1/threats", 1000)
}

// Stream each threat into Steampipe
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

		// Stop if the query’s limit has been reached
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	return nil, nil
}
