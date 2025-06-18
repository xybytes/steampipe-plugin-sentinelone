package sentinelone

import (
	"context"
	"encoding/json"

	sdkproto "github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

// top-level “envelope” for a single alert
type SentinelOneAlertFull struct {
	AlertInfo           AlertInfo   `json:"alertInfo"`
	RuleInfo            RuleInfo    `json:"ruleInfo"`
	SourceParentProcess ProcessInfo `json:"sourceParentProcessInfo"`
	//AgentDetectionInfo  AgentDetectionInfo `json:"agentDetectionInfo"`
	TargetProcessInfo TargetProcessInfo `json:"targetProcessInfo"`
}

// corresponds to the JSON object at .alertInfo
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

// corresponds to the JSON object at .ruleInfo
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

// corresponds to the JSON object at .sourceParentProcessInfo
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

// corresponds to the JSON object at .targetProcessInfo
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

func tableSentinelOneAlerts(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "sentinelone_alerts",
		Description: "Get list of alerts",
		List:        &plugin.ListConfig{Hydrate: listSentinelOneAlerts},
		Columns: []*plugin.Column{
			//AlertInfo
			{Name: "alert_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.AlertID")},
			{Name: "indicator_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.IndicatorName")},
			{Name: "dst_port", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.DstPort")},
			{Name: "ti_indicator_comparison_method", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.TIIndicatorComparisonMethod")},
			{Name: "incident_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.IncidentStatus")},
			{Name: "src_ip", Type: sdkproto.ColumnType_INET, Transform: transform.FromField("AlertInfo.SrcIP")},
			{Name: "dst_ip", Type: sdkproto.ColumnType_INET, Transform: transform.FromField("AlertInfo.DstIP")},
			{Name: "src_port", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.SrcPort")},
			{Name: "dns_request", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.DNSRequest")},
			{Name: "dns_response", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.DNSResponse")},
			{Name: "net_event_direction", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.NetEventDirection")},
			{Name: "is_edr", Type: sdkproto.ColumnType_BOOL, Transform: transform.FromField("AlertInfo.IsEDR")},
			{Name: "login_is_successful", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.LoginIsSuccessful")},
			{Name: "login_is_administrator_equivalent", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.LoginIsAdministratorEquiv")},
			{Name: "login_account_domain", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.LoginAccountDomain")},
			{Name: "login_account_sid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.LoginAccountSid")},
			{Name: "login_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.LoginType")},
			{Name: "logins_user_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.LoginsUserName")},
			{Name: "dv_event_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.DVEventID")},
			{Name: "hit_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.HitType")},
			{Name: "source", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.Source")},
			{Name: "registry_key_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.RegistryKeyPath")},
			{Name: "registry_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.RegistryPath")},
			{Name: "registry_value", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.RegistryValue")},
			{Name: "registry_old_value", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.RegistryOldValue")},
			{Name: "registry_old_value_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.RegistryOldValueType")},
			{Name: "module_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.ModulePath")},
			{Name: "module_sha1", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.ModuleSha1")},
			{Name: "indicator_category", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.IndicatorCategory")},
			{Name: "indicator_description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.IndicatorDescription")},
			{Name: "analyst_verdict", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.AnalystVerdict")},
			{Name: "ti_indicator_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.TIIndicatorType")},
			{Name: "ti_indicator_source", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.TIIndicatorSource")},
			{Name: "ti_indicator_value", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AlertInfo.TIIndicatorValue")},
			{Name: "updated_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("AlertInfo.UpdatedAt")},
			{Name: "created_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("AlertInfo.CreatedAt")},
			{Name: "reported_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("AlertInfo.ReportedAt")},
			{Name: "rule_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleID")},
			{Name: "rule_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleName")},
			{Name: "rule_query_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleQueryType")},
			{Name: "rule_s1ql", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleS1QL")},
			{Name: "rule_scope_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleScopeLevel")},
			{Name: "rule_description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleDescription")},
			{Name: "rule_query_lang", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleQueryLang")},
			{Name: "rule_severity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleSeverity")},
			{Name: "rule_treat_as_threat", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("RuleInfo.RuleTreatAsThreat")},
			//SourceParentProcess
			{Name: "source_parent_integrity_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.IntegrityLevel")},
			{Name: "source_parent_commandline", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.Commandline")},
			{Name: "source_parent_file_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.FilePath")},
			{Name: "source_parent_file_hash_md5", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.FileHashMd5")},
			{Name: "source_parent_file_hash_sha1", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.FileHashSha1")},
			{Name: "source_parent_file_hash_sha256", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.FileHashSha256")},
			{Name: "source_parent_login_user", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.LoginUser")},
			{Name: "source_parent_real_user", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.RealUser")},
			{Name: "source_parent_user", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.User")},
			{Name: "source_parent_subsystem", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.Subsystem")},
			{Name: "source_parent_effective_user", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.EffectiveUser")},
			{Name: "source_parent_pid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.PID")},
			{Name: "source_parent_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.Name")},
			{Name: "source_parent_file_signer_identity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.FileSignerIdentity")},
			{Name: "source_parent_storyline", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.Storyline")},
			{Name: "source_parent_pid_start_time", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("SourceParentProcess.PIDStartTime")},
			{Name: "source_parent_unique_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SourceParentProcess.UniqueID")},
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
			{Name: "target_file_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.FilePath")},
			{Name: "target_file_is_signed", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.FileIsSigned")},
			{Name: "target_proc_signed_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcSignedStatus")},
			{Name: "target_file_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.FileID")},
			{Name: "target_file_hash_sha256", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.FileHashSha256")},
			{Name: "target_proc_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcName")},
			{Name: "target_proc_cmd_line", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcCmdLine")},
			{Name: "target_file_created_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("TargetProcessInfo.FileCreatedAt")},
			{Name: "target_proc_image_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcImagePath")},
			{Name: "target_file_modified_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("TargetProcessInfo.FileModifiedAt")},
			{Name: "target_proc_integrity_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcIntegrityLevel")},
			{Name: "target_process_start_time", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("TargetProcessInfo.ProcessStartTime")},
			{Name: "target_proc_pid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcPID")},
			{Name: "target_proc_uid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcUID")},
			{Name: "target_file_old_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.FileOldPath")},
			{Name: "target_file_hash_sha1", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.FileHashSha1")},
			{Name: "target_proc_storyline_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("TargetProcessInfo.ProcStorylineID")},
		},
	}
}

// ListThreatsRaw retrieves paginated threat data
func (t *SentinelOneClient) ListAlertsRaw(ctx context.Context, d *plugin.QueryData) (
	[]interface{},
	map[string]interface{},
	[]interface{},
	error,
) {
	// passing in: the request context, the query data (for SQL LIMIT), the API endpoint, the maximum page size per HTTP call
	return t.fetchPaginatedData(ctx, d, "/web/api/v2.1/cloud-detection/alerts", 1000)
}

// Stream each alert into Steampipe
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
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		b, _ := json.Marshal(m)

		var threat SentinelOneAlertFull
		if err := json.Unmarshal(b, &threat); err != nil {
			plugin.Logger(ctx).Error("SentinelOneAlertFull", "unmarshal_error", err)
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
