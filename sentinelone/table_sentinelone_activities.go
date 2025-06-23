package sentinelone

import (
	"context"
	"encoding/json"
	"time"

	sdkproto "github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

type ActivityData struct {
	AccountId                         string    `json:"accountId"`
	AccountName                       string    `json:"accountName"`
	ActorAlternateID                  string    `json:"actoralternateid"`
	AgentIPv4                         string    `json:"agentipv4"`
	AlertID                           string    `json:"alertid"`
	CommandCorrelationID              string    `json:"commandCorrelationid"`
	DataSourceName                    string    `json:"datasourcename"`
	DetectedAt                        time.Time `json:"detectedat"`
	DNSRequest                        string    `json:"dnsrequest"`
	DNSResponse                       string    `json:"dnsresponse"`
	DstIP                             string    `json:"dstip"`
	DstPort                           int       `json:"dstport"`
	DvEventID                         string    `json:"dveventid"`
	DvEventType                       string    `json:"dveventtype"`
	EventCategory                     string    `json:"eventcategory"`
	EventDetails                      string    `json:"eventdetails"`
	EventExternalID                   string    `json:"eventexternalid"`
	EventTime                         int64     `json:"eventtime"`
	ExternalServiceID                 *string   `json:"externalServiceId"`
	ExternalIP                        string    `json:"externalip"`
	ExternalThreatValue               string    `json:"externalthreatvalue"`
	FullScopeDetails                  string    `json:"fullScopeDetails"`
	FullScopeDetailsPath              string    `json:"fullScopeDetailsPath"`
	GroupName                         string    `json:"groupName"`
	IndicatorCategory                 string    `json:"indicatorcategory"`
	IndicatorDescription              string    `json:"indicatordescription"`
	IndicatorName                     string    `json:"indicatorname"`
	IPAddress                         *string   `json:"ipAddress"`
	LoginAccountDomain                string    `json:"loginaccountdomain"`
	LoginAccountSID                   string    `json:"loginaccountsid"`
	LoginIsAdministratorEq            string    `json:"loginisadministratorequivalent"`
	LoginIsSuccessful                 string    `json:"loginissuccessful"`
	LogonSUserName                    string    `json:"loginsusername"`
	LoginType                         string    `json:"logintype"`
	ModulePath                        string    `json:"modulepath"`
	ModuleSHA1                        string    `json:"modulesha1"`
	NetEventDirection                 string    `json:"neteventdirection"`
	OrigAgentMachineType              string    `json:"origagentmachinetype"`
	OrigAgentName                     string    `json:"origagentname"`
	OrigAgentOSFamily                 string    `json:"origagentosfamily"`
	OrigAgentOSName                   string    `json:"origagentosname"`
	OrigAgentOSRevision               string    `json:"origagentosrevision"`
	OrigAgentSiteID                   string    `json:"origagentsiteid"`
	OrigAgentUUID                     string    `json:"origagentuuid"`
	OrigAgentVersion                  string    `json:"origagentversion"`
	Physical                          string    `json:"physical"`
	RealUser                          *string   `json:"realUser"`
	RegistryKeyPath                   string    `json:"registrykeypath"`
	RegistryOldValue                  string    `json:"registryoldvalue"`
	RegistryOldValueType              string    `json:"registryoldvaluetype"`
	RegistryPath                      string    `json:"registrypath"`
	RegistryValue                     string    `json:"registryvalue"`
	RuleDescription                   string    `json:"ruledescription"`
	RuleID                            string    `json:"ruleid"`
	RuleName                          string    `json:"rulename"`
	RuleScopeID                       int64     `json:"rulescopeid"`
	RuleScopeLevel                    string    `json:"rulescopelevel"`
	ScopeID                           int64     `json:"scopeId"`
	ScopeLevel                        string    `json:"scopeLevel"`
	ScopeName                         string    `json:"scopeName"`
	Severity                          string    `json:"severity"`
	SiteID                            string    `json:"siteId"`
	SiteName                          string    `json:"siteName"`
	SourceName                        string    `json:"sourcename"`
	SourceParentProcessCommandLine    string    `json:"sourceparentprocesscommandline"`
	SourceParentProcessIntegrityLevel string    `json:"sourceparentprocessintegritylevel"`
	SourceParentProcessKey            string    `json:"sourceparentprocesskey"`
	SourceParentProcessMD5            string    `json:"sourceparentprocessmd5"`
	SourceParentProcessName           string    `json:"sourceparentprocessname"`
	SourceParentProcessPath           string    `json:"sourceparentprocesspath"`
	SourceParentProcessPID            int       `json:"sourceparentprocesspid"`
	SourceParentProcessSHA1           string    `json:"sourceparentprocesssha1"`
	SourceParentProcessSHA256         string    `json:"sourceparentprocesssha256"`
	SourceParentProcessSignerIdentity string    `json:"sourceparentprocesssigneridentity"`
	SourceParentProcessStoryline      string    `json:"sourceparentprocessstoryline"`
	SourceParentProcessSubsystem      string    `json:"sourceparentprocesssubsystem"`
	SourceParentProcessUserName       string    `json:"sourceparentprocessusername"`
	SourceProcessCommandLine          string    `json:"sourceprocesscommandline"`
	SourceProcessFilePath             string    `json:"sourceprocessfilepath"`
	SourceProcessFileSignerIdentity   string    `json:"sourceprocessfilesigneridentity"`
	SourceProcessIntegrityLevel       string    `json:"sourceprocessintegritylevel"`
	SourceProcessKey                  string    `json:"sourceprocesskey"`
	SourceProcessMD5                  string    `json:"sourceprocessmd5"`
	SourceProcessName                 string    `json:"sourceprocessname"`
	SourceProcessPID                  int       `json:"sourceprocesspid"`
	SourceProcessSHA1                 string    `json:"sourceprocesssha1"`
	SourceProcessSHA256               string    `json:"sourceprocesssha256"`
	SourceProcessStoryline            string    `json:"sourceprocessstoryline"`
	SourceProcessSubsystem            string    `json:"sourceprocesssubsystem"`
	SourceProcessUserName             string    `json:"sourceprocessusername"`
	SrcIP                             string    `json:"srcip"`
	SrcMachineIP                      string    `json:"srcmachineip"`
	SrcPort                           int       `json:"srcport"`
	SystemUser                        int       `json:"systemUser"`
	TgtFileHashSHA1                   string    `json:"tgtfilehashsha1"`
	TgtFileHashSHA256                 string    `json:"tgtfilehashsha256"`
	TgtFileID                         string    `json:"tgtfileid"`
	TgtFileIsSigned                   string    `json:"tgtfileissigned"`
	TgtFileOldPath                    string    `json:"tgtfileoldpath"`
	TgtFilePath                       string    `json:"tgtfilepath"`
	TgtProcCmdLine                    string    `json:"tgtproccmdline"`
	TgtProcImagePath                  string    `json:"tgtprocimagepath"`
	TgtProcIntegrityLevel             string    `json:"tgtprocintegritylevel"`
	TgtProcName                       string    `json:"tgtprocname"`
	TgtProcPID                        int       `json:"tgtprocpid"`
	TgtProcSignedStatus               string    `json:"tgtprocsignedstatus"`
	TgtProcStorylineID                string    `json:"tgtprocstorylineid"`
	TgtProcUID                        string    `json:"tgtprocuid"`
	TIIndicatorComparisonMethod       string    `json:"tiindicatorcomparisonmethod"`
	TIIndicatorSource                 string    `json:"tiindicatorsource"`
	TIIndicatorType                   string    `json:"tiindicatortype"`
	TIIndicatorValue                  string    `json:"tiindicatorvalue"`
	UserID                            int64     `json:"userId"`
	UserName                          string    `json:"userName"`
}

type SentinelOneActivityFull struct {
	AccountId            string       `json:"accountId"`
	AccountName          string       `json:"accountName"`
	ActivityType         int          `json:"activityType"`
	ActivityUuid         string       `json:"activityUuid"`
	AgentId              string       `json:"agentId"`
	AgentUpdatedVersion  *string      `json:"agentUpdatedVersion"`
	Comments             *string      `json:"comments"`
	CreatedAt            time.Time    `json:"createdAt"`
	Data                 ActivityData `json:"data"`
	Description          *string      `json:"description"`
	GroupId              string       `json:"groupId"`
	GroupName            string       `json:"groupName"`
	Hash                 *string      `json:"hash"`
	Id                   string       `json:"id"`
	OsFamily             *string      `json:"osFamily"`
	PrimaryDescription   string       `json:"primaryDescription"`
	SecondaryDescription string       `json:"secondaryDescription"`
	SiteId               string       `json:"siteId"`
	SiteName             string       `json:"siteName"`
	ThreatId             *string      `json:"threatId"`
	UpdatedAt            time.Time    `json:"updatedAt"`
}

func tableSentinelOneActivities(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "sentinelone_activities",
		Description: "Get the activities and their data",
		List: &plugin.ListConfig{
			Hydrate: listSentinelOneActivity,
		},
		Columns: []*plugin.Column{
			// Root Level
			{Name: "account_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AccountId")},
			{Name: "account_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AccountName")},
			{Name: "activity_type", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("ActivityType")},
			{Name: "activity_uuid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ActivityUuid")},
			{Name: "agent_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentId")},
			{Name: "agent_updated_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentUpdatedVersion")},
			{Name: "comments", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Comments")},
			{Name: "created_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("CreatedAt")},
			{Name: "description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Description")},
			{Name: "group_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("GroupId")},
			{Name: "group_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("GroupName")},
			{Name: "hash", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Hash")},
			{Name: "id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Id")},
			{Name: "os_family", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OsFamily")},
			{Name: "primary_description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("PrimaryDescription")},
			{Name: "secondary_description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SecondaryDescription")},
			{Name: "site_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SiteId")},
			{Name: "site_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SiteName")},
			{Name: "threat_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatId")},
			{Name: "updated_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("UpdatedAt")},

			// Data
			{Name: "data_account_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.AccountId")},
			{Name: "data_account_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.AccountName")},
			{Name: "data_actor_alternate_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ActorAlternateID")},
			{Name: "data_agent_ipv4", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.AgentIPv4")},
			{Name: "data_alert_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.AlertID")},
			{Name: "data_command_correlation_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.CommandCorrelationID")},
			{Name: "data_datasource_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.DataSourceName")},
			{Name: "data_detected_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("Data.DetectedAt")},
			{Name: "data_dns_request", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.DNSRequest")},
			{Name: "data_dns_response", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.DNSResponse")},
			{Name: "data_dst_ip", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.DstIP")},
			{Name: "data_dst_port", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.DstPort")},
			{Name: "data_dv_event_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.DvEventID")},
			{Name: "data_dv_event_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.DvEventType")},
			{Name: "data_event_category", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.EventCategory")},
			{Name: "data_event_details", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.EventDetails")},
			{Name: "data_event_external_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.EventExternalID")},
			{Name: "data_external_service_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ExternalServiceID")},
			{Name: "data_external_ip", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ExternalIP")},
			{Name: "data_external_threat_value", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ExternalThreatValue")},
			{Name: "data_full_scope_details", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.FullScopeDetails")},
			{Name: "data_full_scope_details_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.FullScopeDetailsPath")},
			{Name: "data_indicator_category", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.IndicatorCategory")},
			{Name: "data_indicator_description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.IndicatorDescription")},
			{Name: "data_indicator_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.IndicatorName")},
			{Name: "data_ip_address", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.IPAddress")},
			{Name: "data_login_account_domain", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.LoginAccountDomain")},
			{Name: "data_login_account_sid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.LoginAccountSID")},
			{Name: "data_login_is_administrator_eq", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.LoginIsAdministratorEq")},
			{Name: "data_login_is_successful", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.LoginIsSuccessful")},
			{Name: "data_logons_username", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.LogonSUserName")},
			{Name: "data_login_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.LoginType")},
			{Name: "data_module_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ModulePath")},
			{Name: "data_module_sha1", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ModuleSHA1")},
			{Name: "data_net_event_direction", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.NetEventDirection")},
			{Name: "data_origagent_machine_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentMachineType")},
			{Name: "data_origagent_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentName")},
			{Name: "data_origagent_os_family", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentOSFamily")},
			{Name: "data_origagent_os_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentOSName")},
			{Name: "data_origagent_os_revision", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentOSRevision")},
			{Name: "data_origagent_site_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentSiteID")},
			{Name: "data_origagent_uuid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentUUID")},
			{Name: "data_origagent_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentVersion")},
			{Name: "data_physical", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.Physical")},
			{Name: "data_real_user", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RealUser")},
			{Name: "data_registry_key_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RegistryKeyPath")},
			{Name: "data_registry_old_value", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RegistryOldValue")},
			{Name: "data_registry_old_value_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RegistryOldValueType")},
			{Name: "data_registry_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RegistryPath")},
			{Name: "data_registry_value", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RegistryValue")},
			{Name: "data_rule_description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RuleDescription")},
			{Name: "data_rule_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RuleID")},
			{Name: "data_rule_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RuleName")},
			{Name: "data_rule_scope_id", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.RuleScopeID")},
			{Name: "data_rule_scope_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RuleScopeLevel")},
			{Name: "data_scope_id", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.ScopeID")},
			{Name: "data_scope_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ScopeLevel")},
			{Name: "data_scope_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ScopeName")},
			{Name: "data_severity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.Severity")},
			{Name: "data_sourcename", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceName")},
			{Name: "data_sourceparentprocess_commandline", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessCommandLine")},
			{Name: "data_sourceparentprocess_integrity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessIntegrityLevel")},
			{Name: "data_sourceparentprocess_key", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessKey")},
			{Name: "data_sourceparentprocess_md5", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessMD5")},
			{Name: "data_sourceparentprocess_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessName")},
			{Name: "data_sourceparentprocess_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessPath")},
			{Name: "data_sourceparentprocess_pid", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.SourceParentProcessPID")},
			{Name: "data_sourceparentprocess_sha1", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessSHA1")},
			{Name: "data_sourceparentprocess_sha256", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessSHA256")},
			{Name: "data_sourceparentprocess_signer", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessSignerIdentity")},
			{Name: "data_sourceparentprocess_storyline", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessStoryline")},
			{Name: "data_sourceparentprocess_subsystem", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessSubsystem")},
			{Name: "data_sourceparentprocess_username", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessUserName")},
			{Name: "data_sourceprocess_commandline", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessCommandLine")},
			{Name: "data_sourceprocess_filepath", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessFilePath")},
			{Name: "data_sourceprocess_signeridentity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessFileSignerIdentity")},
			{Name: "data_sourceprocess_integrity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessIntegrityLevel")},
			{Name: "data_sourceprocess_key", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessKey")},
			{Name: "data_sourceprocess_md5", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessMD5")},
			{Name: "data_sourceprocess_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessName")},
			{Name: "data_sourceprocess_pid", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.SourceProcessPID")},
			{Name: "data_sourceprocess_sha1", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessSHA1")},
			{Name: "data_sourceprocess_sha256", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessSHA256")},
			{Name: "data_sourceprocess_storyline", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessStoryline")},
			{Name: "data_sourceprocess_subsystem", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessSubsystem")},
			{Name: "data_sourceprocess_username", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessUserName")},
			{Name: "data_src_ip", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SrcIP")},
			{Name: "data_src_machine_ip", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SrcMachineIP")},
			{Name: "data_src_port", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.SrcPort")},
			{Name: "data_system_user", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.SystemUser")},
			{Name: "data_tgtfile_hash_sha1", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtFileHashSHA1")},
			{Name: "data_tgtfile_hash_sha256", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtFileHashSHA256")},
			{Name: "data_tgtfile_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtFileID")},
			{Name: "data_tgtfile_is_signed", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtFileIsSigned")},
			{Name: "data_tgtfile_old_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtFileOldPath")},
			{Name: "data_tgtfile_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtFilePath")},
			{Name: "data_tgtproc_cmd_line", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtProcCmdLine")},
			{Name: "data_tgtproc_image_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtProcImagePath")},
			{Name: "data_tgtproc_integrity_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtProcIntegrityLevel")},
			{Name: "data_tgtproc_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtProcName")},
			{Name: "data_tgtproc_pid", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.TgtProcPID")},
			{Name: "data_tgtproc_signed_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtProcSignedStatus")},
			{Name: "data_tgtproc_storyline_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtProcStorylineID")},
			{Name: "data_tgtproc_uid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtProcUID")},
			{Name: "data_ti_indicator_comparison_method", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TIIndicatorComparisonMethod")},
			{Name: "data_ti_indicator_source", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TIIndicatorSource")},
			{Name: "data_ti_indicator_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TIIndicatorType")},
			{Name: "data_ti_indicator_value", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TIIndicatorValue")}},
	}
}

// Retrieves paginated activities data
func (t *SentinelOneClient) ListActivitiesRaw(ctx context.Context, d *plugin.QueryData) (
	[]interface{},
	map[string]interface{},
	[]interface{},
	error,
) {
	// passing in: the request context, the query data (for SQL LIMIT), the API endpoint, the maximum page size per HTTP call
	return t.fetchPaginatedData(ctx, d, "/web/api/v2.1/activities", 1000)
}

func listSentinelOneActivity(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	client, err := Connect(ctx, d)
	if err != nil {
		return nil, err
	}

	rawData, _, _, err := client.ListActivitiesRaw(ctx, d)
	if err != nil {
		return nil, err
	}

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

		var activity SentinelOneActivityFull
		if err := json.Unmarshal(b, &activity); err != nil {
			plugin.Logger(ctx).Error("sentinelone_activity", "unmarshal_error", err)
			continue
		}

		// Stream the item into Steampipe
		d.StreamListItem(ctx, activity)

		// Stop if the query’s SQL LIMIT has been reached
		if d.RowsRemaining(ctx) == 0 {
			return nil, nil
		}
	}

	return nil, nil
}
