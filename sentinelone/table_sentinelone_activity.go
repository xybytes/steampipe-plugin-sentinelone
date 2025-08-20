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

// Defines the Steampipe table
func tableSentinelOneActivities(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "sentinelone_activity",
		Description: "Get the activities and their data.",
		List: &plugin.ListConfig{
			Hydrate: listSentinelOneActivity,
		},
		Columns: []*plugin.Column{
			// Root Level
			{Name: "account_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AccountId"), Description: "Unique identifier for the account involved in the event."},
			{Name: "account_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AccountName"), Description: "Name of the account related to the activity or alert."},
			{Name: "activity_type", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("ActivityType"), Description: "Integer representing the type of activity detected."},
			{Name: "activity_uuid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ActivityUuid"), Description: "Unique identifier for the specific activity instance."},
			{Name: "agent_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentId"), Description: "Identifier of the agent that collected or generated the event."},
			{Name: "agent_updated_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("AgentUpdatedVersion"), Description: "Version of the agent software at the time of the event."},
			{Name: "comments", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Comments"), Description: "User-generated comments or notes related to the event."},
			{Name: "created_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("CreatedAt"), Description: "Timestamp indicating when the event or record was created."},
			{Name: "description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Description"), Description: "General description or summary of the activity."},
			{Name: "group_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("GroupId"), Description: "Identifier of the group associated with the agent or account."},
			{Name: "group_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("GroupName"), Description: "Name of the group associated with the agent or account."},
			{Name: "hash", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Hash"), Description: "Hash value used to uniquely identify the event or object."},
			{Name: "id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Id"), Description: "Unique identifier of the record or event."},
			{Name: "os_family", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("OsFamily"), Description: "Operating system family (e.g. Windows, Linux) of the monitored system."},
			{Name: "primary_description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("PrimaryDescription"), Description: "Main textual description providing a summary of the event."},
			{Name: "secondary_description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SecondaryDescription"), Description: "Additional description providing extended context or technical details."},
			{Name: "site_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SiteId"), Description: "Unique identifier of the site or deployment location of the agent."},
			{Name: "site_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("SiteName"), Description: "Name of the site or physical location where the agent is deployed."},
			{Name: "threat_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("ThreatId"), Description: "Identifier referencing the threat object or detection signature."},
			{Name: "updated_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("UpdatedAt"), Description: "Timestamp indicating the last update made to the record."},

			// Data
			{Name: "data_account_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.AccountId"), Description: "Unique identifier of the account involved in the event data."},
			{Name: "data_account_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.AccountName"), Description: "Name of the account associated with the event data."},
			{Name: "data_actor_alternate_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ActorAlternateID"), Description: "Alternate identifier of the actor that triggered the event."},
			{Name: "data_agent_ipv4", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.AgentIPv4"), Description: "IPv4 address of the agent reporting the event data."},
			{Name: "data_alert_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.AlertID"), Description: "Identifier linking this record to a broader alert object."},
			{Name: "data_command_correlation_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.CommandCorrelationID"), Description: "Correlation ID used to group related command executions."},
			{Name: "data_datasource_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.DataSourceName"), Description: "Name of the data source that originated this event information."},
			{Name: "data_detected_at", Type: sdkproto.ColumnType_TIMESTAMP, Transform: transform.FromField("Data.DetectedAt"), Description: "Timestamp when the detection originally occurred."},
			{Name: "data_dns_request", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.DNSRequest"), Description: "Fully qualified domain name (FQDN) used in the DNS request."},
			{Name: "data_dns_response", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.DNSResponse"), Description: "Response returned by the DNS server for the query."},
			{Name: "data_dst_ip", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.DstIP"), Description: "Destination IP address in the network event."},
			{Name: "data_dst_port", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.DstPort"), Description: "Destination port number for the network traffic."},
			{Name: "data_dv_event_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.DvEventID"), Description: "Identifier of the device-level event."},
			{Name: "data_dv_event_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.DvEventType"), Description: "Type of the device-level event recorded."},
			{Name: "data_event_category", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.EventCategory"), Description: "Category assigned to the event for classification purposes."},
			{Name: "data_event_details", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.EventDetails"), Description: "Detailed description of the event occurrence."},
			{Name: "data_event_external_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.EventExternalID"), Description: "External identifier associated with the event."},
			{Name: "data_external_service_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ExternalServiceID"), Description: "Identifier of the external service related to this data."},
			{Name: "data_external_ip", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ExternalIP"), Description: "External IP address involved in the event."},
			{Name: "data_external_threat_value", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ExternalThreatValue"), Description: "Threat score provided by an external intelligence source."},
			{Name: "data_full_scope_details", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.FullScopeDetails"), Description: "Comprehensive details of the full scope of the event."},
			{Name: "data_full_scope_details_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.FullScopeDetailsPath"), Description: "File path or URL to retrieve the full scope details."},
			{Name: "data_indicator_category", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.IndicatorCategory"), Description: "Category of the threat intelligence indicator."},
			{Name: "data_indicator_description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.IndicatorDescription"), Description: "Textual description of the threat intelligence indicator."},
			{Name: "data_indicator_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.IndicatorName"), Description: "Name of the threat intelligence indicator."},
			{Name: "data_ip_address", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.IPAddress"), Description: "IP address involved in this event data."},
			{Name: "data_login_account_domain", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.LoginAccountDomain"), Description: "Domain of the account used in the login attempt."},
			{Name: "data_login_account_sid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.LoginAccountSID"), Description: "Security identifier (SID) of the login account."},
			{Name: "data_login_is_administrator_eq", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.LoginIsAdministratorEq"), Description: "Boolean flag indicating if the login account has administrator privileges."},
			{Name: "data_login_is_successful", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.LoginIsSuccessful"), Description: "Indicates whether the login attempt succeeded."},
			{Name: "data_logons_username", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.LogonSUserName"), Description: "Username used in the logon session."},
			{Name: "data_login_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.LoginType"), Description: "Numeric code representing the type of login."},
			{Name: "data_module_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ModulePath"), Description: "Filesystem path of the module involved in the event."},
			{Name: "data_module_sha1", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ModuleSHA1"), Description: "SHA1 hash of the module binary."},
			{Name: "data_net_event_direction", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.NetEventDirection"), Description: "Direction of the network event (e.g., inbound, outbound)."},
			{Name: "data_origagent_machine_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentMachineType"), Description: "Type of machine on which the original agent ran."},
			{Name: "data_origagent_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentName"), Description: "Name of the original agent reporting the event."},
			{Name: "data_origagent_os_family", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentOSFamily"), Description: "Operating system family of the original agent."},
			{Name: "data_origagent_os_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentOSName"), Description: "Name of the operating system of the original agent."},
			{Name: "data_origagent_os_revision", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentOSRevision"), Description: "OS revision or build number of the original agent."},
			{Name: "data_origagent_site_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentSiteID"), Description: "Site identifier where the original agent was deployed."},
			{Name: "data_origagent_uuid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentUUID"), Description: "UUID of the original agent instance."},
			{Name: "data_origagent_version", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.OrigAgentVersion"), Description: "Version of the original agent software."},
			{Name: "data_physical", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.Physical"), Description: "Physical location or device identifier associated with the event."},
			{Name: "data_real_user", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RealUser"), Description: "Actual user account under which the event occurred."},
			{Name: "data_registry_key_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RegistryKeyPath"), Description: "Path of the registry key modified during the event."},
			{Name: "data_registry_old_value", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RegistryOldValue"), Description: "Previous value of the registry key before modification."},
			{Name: "data_registry_old_value_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RegistryOldValueType"), Description: "Data type of the old registry value."},
			{Name: "data_registry_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RegistryPath"), Description: "Full registry path affected by the event."},
			{Name: "data_registry_value", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RegistryValue"), Description: "New value of the registry key after modification."},
			{Name: "data_rule_description", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RuleDescription"), Description: "Description of the security rule that triggered this event."},
			{Name: "data_rule_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RuleID"), Description: "Identifier of the security rule applied."},
			{Name: "data_rule_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RuleName"), Description: "Name of the security rule that matched the event."},
			{Name: "data_rule_scope_id", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.RuleScopeID"), Description: "Identifier of the scope in which the rule was evaluated."},
			{Name: "data_rule_scope_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.RuleScopeLevel"), Description: "Level at which the rule scope was defined (e.g., account, site)."},
			{Name: "data_scope_id", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.ScopeID"), Description: "Identifier of the specific scope related to the event."},
			{Name: "data_scope_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ScopeLevel"), Description: "Level of the scope associated with this event (e.g., machine, user)."},
			{Name: "data_scope_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.ScopeName"), Description: "Name of the scope associated with the event."},
			{Name: "data_severity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.Severity"), Description: "Severity level assigned to the event based on internal scoring."},
			{Name: "data_sourcename", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceName"), Description: "Name of the source entity that generated the data."},
			{Name: "data_sourceparentprocess_commandline", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessCommandLine"), Description: "Command line arguments of the parent process."},
			{Name: "data_sourceparentprocess_integrity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessIntegrityLevel"), Description: "Integrity level of the parent process."},
			{Name: "data_sourceparentprocess_key", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessKey"), Description: "Unique key of the parent process for correlation."},
			{Name: "data_sourceparentprocess_md5", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessMD5"), Description: "MD5 hash of the parent process binary."},
			{Name: "data_sourceparentprocess_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessName"), Description: "Name of the parent process."},
			{Name: "data_sourceparentprocess_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessPath"), Description: "Filesystem path of the parent process executable."},
			{Name: "data_sourceparentprocess_pid", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.SourceParentProcessPID"), Description: "Process ID of the parent process."},
			{Name: "data_sourceparentprocess_sha1", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessSHA1"), Description: "SHA1 hash of the parent process binary."},
			{Name: "data_sourceparentprocess_sha256", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessSHA256"), Description: "SHA256 hash of the parent process binary."},
			{Name: "data_sourceparentprocess_signer", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessSignerIdentity"), Description: "Signer identity of the parent process executable."},
			{Name: "data_sourceparentprocess_storyline", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessStoryline"), Description: "Storyline identifier used for threat correlation."},
			{Name: "data_sourceparentprocess_subsystem", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessSubsystem"), Description: "Subsystem type of the parent process executable."},
			{Name: "data_sourceparentprocess_username", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceParentProcessUserName"), Description: "Username under which the parent process was executed."},
			{Name: "data_sourceprocess_commandline", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessCommandLine"), Description: "Command line arguments of the source process."},
			{Name: "data_sourceprocess_filepath", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessFilePath"), Description: "Filesystem path of the source process executable."},
			{Name: "data_sourceprocess_signeridentity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessFileSignerIdentity"), Description: "Signer identity of the source process executable."},
			{Name: "data_sourceprocess_integrity", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessIntegrityLevel"), Description: "Integrity level of the source process."},
			{Name: "data_sourceprocess_key", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessKey"), Description: "Unique key of the source process for correlation."},
			{Name: "data_sourceprocess_md5", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessMD5"), Description: "MD5 hash of the source process binary."},
			{Name: "data_sourceprocess_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessName"), Description: "Name of the source process."},
			{Name: "data_sourceprocess_pid", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.SourceProcessPID"), Description: "Process ID of the source process."},
			{Name: "data_sourceprocess_sha1", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessSHA1"), Description: "SHA1 hash of the source process binary."},
			{Name: "data_sourceprocess_sha256", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessSHA256"), Description: "SHA256 hash of the source process binary."},
			{Name: "data_sourceprocess_storyline", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessStoryline"), Description: "Storyline identifier for the source process."},
			{Name: "data_sourceprocess_subsystem", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessSubsystem"), Description: "Subsystem type of the source process executable."},
			{Name: "data_sourceprocess_username", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SourceProcessUserName"), Description: "Username under which the source process was executed."},
			{Name: "data_src_ip", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SrcIP"), Description: "Source IP address for the network event."},
			{Name: "data_src_machine_ip", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.SrcMachineIP"), Description: "IP address of the machine generating the event."},
			{Name: "data_src_port", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.SrcPort"), Description: "Source port used for the network communication."},
			{Name: "data_system_user", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.SystemUser"), Description: "Identifier of the system user account under which the event occurred."},
			{Name: "data_tgtfile_hash_sha1", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtFileHashSHA1"), Description: "SHA1 hash of the targeted file."},
			{Name: "data_tgtfile_hash_sha256", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtFileHashSHA256"), Description: "SHA256 hash of the targeted file."},
			{Name: "data_tgtfile_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtFileID"), Description: "Identifier of the targeted file."},
			{Name: "data_tgtfile_is_signed", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtFileIsSigned"), Description: "Indicates if the targeted file is digitally signed."},
			{Name: "data_tgtfile_old_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtFileOldPath"), Description: "Previous filesystem path of the targeted file."},
			{Name: "data_tgtfile_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtFilePath"), Description: "Current filesystem path of the targeted file."},
			{Name: "data_tgtproc_cmd_line", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtProcCmdLine"), Description: "Command line arguments used to launch the target process."},
			{Name: "data_tgtproc_image_path", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtProcImagePath"), Description: "Filesystem path of the target process executable."},
			{Name: "data_tgtproc_integrity_level", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtProcIntegrityLevel"), Description: "Integrity level assigned to the target process."},
			{Name: "data_tgtproc_name", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtProcName"), Description: "Name of the target process."},
			{Name: "data_tgtproc_pid", Type: sdkproto.ColumnType_INT, Transform: transform.FromField("Data.TgtProcPID"), Description: "Process ID of the target process."},
			{Name: "data_tgtproc_signed_status", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtProcSignedStatus"), Description: "Digital signature status of the target process."},
			{Name: "data_tgtproc_storyline_id", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtProcStorylineID"), Description: "Storyline identifier for the target process."},
			{Name: "data_tgtproc_uid", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TgtProcUID"), Description: "Unique user identifier under which the target process ran."},
			{Name: "data_ti_indicator_comparison_method", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TIIndicatorComparisonMethod"), Description: "Method used to compare the threat intelligence indicator."},
			{Name: "data_ti_indicator_source", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TIIndicatorSource"), Description: "Source of the threat intelligence indicator."},
			{Name: "data_ti_indicator_type", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TIIndicatorType"), Description: "Type of the threat intelligence indicator."},
			{Name: "data_ti_indicator_value", Type: sdkproto.ColumnType_STRING, Transform: transform.FromField("Data.TIIndicatorValue"), Description: "Value of the threat intelligence indicator."},
		},
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
