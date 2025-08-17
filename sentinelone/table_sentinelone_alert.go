package sentinelone

import (
	"context"
	"encoding/json"

	sdkproto "github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

type SentinelOneAlertFull struct {
	AlertInfo           AlertInfo   `json:"alertInfo"`
	RuleInfo            RuleInfo    `json:"ruleInfo"`
	SourceParentProcess ProcessInfo `json:"sourceParentProcessInfo"`
	//AgentDetectionInfo  AgentDetectionInfo `json:"agentDetectionInfo"`
	TargetProcessInfo TargetProcessInfo `json:"targetProcessInfo"`
}

type AlertInfo struct {
	AlertID                     string `json:"alertId"`
	IndicatorName               string `json:"indicatorName"`
	DstPort                     string `json:"dstPort"`
	TIIndicatorComparisonMethod string `json:"tiIndicatorComparisonMethod"`
	IncidentStatus              string `json:"incidentStatus"`
	SrcIP                       string `json:"srcIp"`
	DstIP                       string `json:"dstIp"`
	SrcPort                     string `json:"srcPort"`
	DNSRequest                  string `json:"dnsRequest"`
	DNSResponse                 string `json:"dnsResponse"`
	NetEventDirection           string `json:"netEventDirection"`
	IsEDR                       bool   `json:"isEdr"`
	LoginIsSuccessful           string `json:"loginIsSuccessful"`
	LoginIsAdministratorEquiv   string `json:"loginIsAdministratorEquivalent"`
	LoginAccountDomain          string `json:"loginAccountDomain"`
	LoginAccountSid             string `json:"loginAccountSid"`
	LoginType                   string `json:"loginType"`
	LoginsUserName              string `json:"loginsUserName"`
	DVEventID                   string `json:"dvEventId"`
	HitType                     string `json:"hitType"`
	Source                      string `json:"source"`
	RegistryKeyPath             string `json:"registryKeyPath"`
	RegistryPath                string `json:"registryPath"`
	RegistryValue               string `json:"registryValue"`
	RegistryOldValue            string `json:"registryOldValue"`
	RegistryOldValueType        string `json:"registryOldValueType"`
	ModulePath                  string `json:"modulePath"`
	ModuleSha1                  string `json:"moduleSha1"`
	IndicatorCategory           string `json:"indicatorCategory"`
	IndicatorDescription        string `json:"indicatorDescription"`
	AnalystVerdict              string `json:"analystVerdict"`
	TIIndicatorType             string `json:"tiIndicatorType"`
	TIIndicatorSource           string `json:"tiIndicatorSource"`
	TIIndicatorValue            string `json:"tiIndicatorValue"`
	UpdatedAt                   string `json:"updatedAt"`
	CreatedAt                   string `json:"createdAt"`
	ReportedAt                  string `json:"reportedAt"`
}

type RuleInfo struct {
	RuleID            string `json:"id"`
	RuleName          string `json:"name"`
	RuleQueryType     string `json:"queryType"`
	RuleS1QL          string `json:"s1ql"`
	RuleScopeLevel    string `json:"scopeLevel"`
	RuleDescription   string `json:"description"`
	RuleQueryLang     string `json:"queryLang"`
	RuleSeverity      string `json:"severity"`
	RuleTreatAsThreat string `json:"treatAsThreat"`
}

type ProcessInfo struct {
	IntegrityLevel     string `json:"integrityLevel"`
	Commandline        string `json:"commandline"`
	FilePath           string `json:"filePath"`
	FileHashMd5        string `json:"fileHashMd5"`
	FileHashSha1       string `json:"fileHashSha1"`
	FileHashSha256     string `json:"fileHashSha256"`
	LoginUser          string `json:"loginUser"`
	RealUser           string `json:"realUser"`
	User               string `json:"user"`
	Subsystem          string `json:"subsystem"`
	EffectiveUser      string `json:"effectiveUser"`
	PID                string `json:"pid"`
	Name               string `json:"name"`
	FileSignerIdentity string `json:"fileSignerIdentity"`
	Storyline          string `json:"storyline"`
	PIDStartTime       string `json:"pidStarttime"`
	UniqueID           string `json:"uniqueId"`
}

type TargetProcessInfo struct {
	FilePath           string `json:"tgtFilePath"`
	FileIsSigned       string `json:"tgtFileIsSigned"`
	ProcSignedStatus   string `json:"tgtProcSignedStatus"`
	FileID             string `json:"tgtFileId"`
	FileHashSha256     string `json:"tgtFileHashSha256"`
	ProcName           string `json:"tgtProcName"`
	ProcCmdLine        string `json:"tgtProcCmdLine"`
	FileCreatedAt      string `json:"tgtFileCreatedAt"`
	ProcImagePath      string `json:"tgtProcImagePath"`
	FileModifiedAt     string `json:"tgtFileModifiedAt"`
	ProcIntegrityLevel string `json:"tgtProcIntegrityLevel"`
	ProcessStartTime   string `json:"tgtProcessStartTime"`
	ProcPID            string `json:"tgtProcPid"`
	ProcUID            string `json:"tgtProcUid"`
	FileOldPath        string `json:"tgtFileOldPath"`
	FileHashSha1       string `json:"tgtFileHashSha1"`
	ProcStorylineID    string `json:"tgtProcStorylineId"`
}

// Defines the Steampipe table
func tableSentinelOneAlerts(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "sentinelone_alert",
		Description: "Get list of alerts",
		List:        &plugin.ListConfig{Hydrate: listSentinelOneAlerts},
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
			//AlertInfo
			{Name: "alert_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.AlertID"), Description: "Unique identifier of the alert."},
			{Name: "indicator_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.IndicatorName"), Description: "Name of the indicator that triggered the alert."},
			{Name: "dst_port", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.DstPort"), Description: "Destination port involved in the network event."},
			{Name: "ti_indicator_comparison_method", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.TIIndicatorComparisonMethod"), Description: "Method used to compare threat intelligence indicators."},
			{Name: "incident_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.IncidentStatus"), Description: "Current status of the incident."},
			{Name: "src_ip", Type: sdkproto.ColumnType_INET, Transform: transform.FromField("AlertInfo.SrcIP"), Description: "Source IP address of the event."},
			{Name: "dst_ip", Type: sdkproto.ColumnType_INET, Transform: transform.FromField("AlertInfo.DstIP"), Description: "Destination IP address of the event."},
			{Name: "src_port", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.SrcPort"), Description: "Source port involved in the network event."},
			{Name: "dns_request", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.DNSRequest"), Description: "DNS request made during the event."},
			{Name: "dns_response", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.DNSResponse"), Description: "DNS response received during the event."},
			{Name: "net_event_direction", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.NetEventDirection"), Description: "Direction of the network event (inbound/outbound)."},
			{Name: "is_edr", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("AlertInfo.IsEDR"), Description: "Whether this alert was generated by the EDR sensor."},
			{Name: "login_is_successful", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.LoginIsSuccessful"), Description: "Indicates if the login was successful."},
			{Name: "login_is_administrator_equivalent", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.LoginIsAdministratorEquiv"), Description: "Indicates if the login had admin‐equivalent rights."},
			{Name: "login_account_domain", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.LoginAccountDomain"), Description: "Domain of the account used for login."},
			{Name: "login_account_sid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.LoginAccountSid"), Description: "Security identifier of the account used for login."},
			{Name: "login_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.LoginType"), Description: "Type of login action (e.g. interactive, network)."},
			{Name: "logins_user_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.LoginsUserName"), Description: "Username used in the login event."},
			{Name: "dv_event_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.DVEventID"), Description: "Digital vigilance event identifier."},
			{Name: "hit_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.HitType"), Description: "Type of detection hit."},
			{Name: "source", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.Source"), Description: "Origin of the alert (e.g. policy, TI)."},
			{Name: "registry_key_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.RegistryKeyPath"), Description: "Path of the registry key involved."},
			{Name: "registry_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.RegistryPath"), Description: "Full registry path involved."},
			{Name: "registry_value", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.RegistryValue"), Description: "Value written to or read from the registry."},
			{Name: "registry_old_value", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.RegistryOldValue"), Description: "Previous value before modification."},
			{Name: "registry_old_value_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.RegistryOldValueType"), Description: "Type of the previous registry value."},
			{Name: "module_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.ModulePath"), Description: "Filesystem path of the module involved."},
			{Name: "module_sha1", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.ModuleSha1"), Description: "SHA1 hash of the module file."},
			{Name: "indicator_category", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.IndicatorCategory"), Description: "Category of the threat intelligence indicator."},
			{Name: "indicator_description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.IndicatorDescription"), Description: "Detailed description of the indicator."},
			{Name: "analyst_verdict", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.AnalystVerdict"), Description: "Verdict given by the security analyst."},
			{Name: "ti_indicator_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.TIIndicatorType"), Description: "Type of threat intelligence indicator."},
			{Name: "ti_indicator_source", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.TIIndicatorSource"), Description: "Source of the threat intelligence indicator."},
			{Name: "ti_indicator_value", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.TIIndicatorValue"), Description: "Value of the threat intelligence indicator."},
			{Name: "updated_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("AlertInfo.UpdatedAt"), Description: "Timestamp when the alert was last updated."},
			{Name: "created_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("AlertInfo.CreatedAt"), Description: "Timestamp when the alert was created."},
			{Name: "reported_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("AlertInfo.ReportedAt"), Description: "Timestamp when the alert was reported."},
			{Name: "rule_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleID"), Description: "Unique identifier of the rule that generated the alert."},
			{Name: "rule_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleName"), Description: "Name of the rule."},
			{Name: "rule_query_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleQueryType"), Description: "Type of query used by the rule."},
			{Name: "rule_s1ql", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleS1QL"), Description: "S1QL query text of the rule."},
			{Name: "rule_scope_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleScopeLevel"), Description: "Scope level at which the rule applies."},
			{Name: "rule_description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleDescription"), Description: "Description of the rule."},
			{Name: "rule_query_lang", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleQueryLang"), Description: "Language used for the rule query."},
			{Name: "rule_severity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleSeverity"), Description: "Severity level of the rule alert."},
			{Name: "rule_treat_as_threat", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleTreatAsThreat"), Description: "Indicates if the rule treats the event as a threat."},

			//SourceParentProcess
			{Name: "source_parent_integrity_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.IntegrityLevel"), Description: "Integrity level of the parent process."},
			{Name: "source_parent_commandline", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.Commandline"), Description: "Command line used to start the parent process."},
			{Name: "source_parent_file_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.FilePath"), Description: "Filesystem path of the parent process executable."},
			{Name: "source_parent_file_hash_md5", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.FileHashMd5"), Description: "MD5 hash of the parent process executable."},
			{Name: "source_parent_file_hash_sha1", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.FileHashSha1"), Description: "SHA1 hash of the parent process executable."},
			{Name: "source_parent_file_hash_sha256", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.FileHashSha256"), Description: "SHA256 hash of the parent process executable."},
			{Name: "source_parent_login_user", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.LoginUser"), Description: "User account that initiated the parent process."},
			{Name: "source_parent_real_user", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.RealUser"), Description: "Real user context of the parent process."},
			{Name: "source_parent_user", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.User"), Description: "Effective user running the parent process."},
			{Name: "source_parent_subsystem", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.Subsystem"), Description: "Subsystem under which the parent process runs."},
			{Name: "source_parent_effective_user", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.EffectiveUser"), Description: "Effective user context of the parent process."},
			{Name: "source_parent_pid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.PID"), Description: "Process ID of the parent process."},
			{Name: "source_parent_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.Name"), Description: "Name of the parent process executable."},
			{Name: "source_parent_file_signer_identity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.FileSignerIdentity"), Description: "Code signer identity of the parent process executable."},
			{Name: "source_parent_storyline", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.Storyline"), Description: "Behavioral storyline associated with the parent process."},
			{Name: "source_parent_pid_start_time", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("SourceParentProcess.PIDStartTime"), Description: "Timestamp when the parent process was started."},
			{Name: "source_parent_unique_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.UniqueID"), Description: "Unique identifier of the parent process instance."},

			// AgentDetectionInfo
			/*{Name: "agent_os_family", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.OSFamily")},
			{Name: "agent_os_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.OSName")},
			{Name: "agent_machine_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.MachineType")},
			{Name: "agent_uuid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.UUID")},
			{Name: "agent_site_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.SiteId")},
			{Name: "agent_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.Name")},
			{Name: "agent_os_revision", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.OSRevision")},
			{Name: "agent_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentDetectionInfo.Version")},*/

			//TargetProcessInfo
			{Name: "target_file_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.FilePath"), Description: "Filesystem path of the target process executable."},
			{Name: "target_file_is_signed", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.FileIsSigned"), Description: "Indicates if the target process executable is signed."},
			{Name: "target_proc_signed_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcSignedStatus"), Description: "Signing status of the target process."},
			{Name: "target_file_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.FileID"), Description: "Identifier of the target process file."},
			{Name: "target_file_hash_sha256", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.FileHashSha256"), Description: "SHA256 hash of the target process executable."},
			{Name: "target_proc_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcName"), Description: "Name of the target process."},
			{Name: "target_proc_cmd_line", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcCmdLine"), Description: "Command line used to start the target process."},
			{Name: "target_file_created_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("TargetProcessInfo.FileCreatedAt"), Description: "Timestamp when the target file was created."},
			{Name: "target_proc_image_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcImagePath"), Description: "Image path of the target process."},
			{Name: "target_file_modified_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("TargetProcessInfo.FileModifiedAt"), Description: "Timestamp when the target file was last modified."},
			{Name: "target_proc_integrity_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcIntegrityLevel"), Description: "Integrity level of the target process."},
			{Name: "target_process_start_time", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("TargetProcessInfo.ProcessStartTime"), Description: "Timestamp when the target process started."},
			{Name: "target_proc_pid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcPID"), Description: "Process ID of the target process."},
			{Name: "target_proc_uid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcUID"), Description: "Unique identifier of the target process user."},
			{Name: "target_file_old_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.FileOldPath"), Description: "Previous filesystem path of the target file."},
			{Name: "target_file_hash_sha1", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.FileHashSha1"), Description: "SHA1 hash of the target process executable."},
			{Name: "target_proc_storyline_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcStorylineID"), Description: "Storyline identifier for the target process behavior."},
		},
	}
}

// retrieves paginated threat data
func (t *SentinelOneClient) ListAlertsRaw(ctx context.Context, d *plugin.QueryData) (
	[]interface{},
	map[string]interface{},
	[]interface{},
	error,
) {
	// passing in: the request context, the query data (for SQL LIMIT), the API endpoint, the maximum page size per HTTP call
	return t.fetchPaginatedData(ctx, d, "/web/api/v2.1/cloud-detection/alerts", 1000)
}

// Stream each alert into Steampipe, respecting context cancellation and SQL LIMIT.
func listSentinelOneAlerts(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	// Establish the API client
	client, err := Connect(ctx, d)
	if err != nil {
		return nil, err
	}

	// Fetch rawData
	rawData, _, _, err := client.ListAlertsRaw(ctx, d)
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

		var alert SentinelOneAlertFull
		if err := json.Unmarshal(b, &alert); err != nil {
			plugin.Logger(ctx).Error("listSentinelOneAlerts", "unmarshal_error", err)
			continue
		}

		// Stream the item into Steampipe
		d.StreamListItem(ctx, alert)

		// Stop if the query’s SQL LIMIT has been reached
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	return nil, nil
}
