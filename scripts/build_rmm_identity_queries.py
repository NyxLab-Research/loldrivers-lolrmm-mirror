"""Data-driven identity enrichment, built from the shared native query templates."""
import json
from pathlib import Path
import re
import rmm_identity as identity
import rmm_report_rules as rr

PROFILE_URL='https://raw.githubusercontent.com/NyxLab-Research/loldrivers-lolrmm-mirror/main/data/rmm_tool_profiles.csv'

def mde_source(inline=False):
    if inline:
        return 'datatable('+','.join(k+':string' for k in identity.FIELDS)+')[\n'+',\n'.join(','.join(rr.quote(r[k]) for k in identity.FIELDS) for r in identity.rows())+'\n]'
    return 'externaldata('+','.join(k+':string' for k in identity.FIELDS)+f")[h'{PROFILE_URL}'] with(format='csv', ignoreFirstRecord=true)"

def profile_query():
    return '''dataset = rmm_tool_profiles
    | filter record_type = "profile" and release in (
        dataset = rmm_tool_profiles | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
    | fields tool_id as _profile_id, tool_name as _profile_tool, process_name as _profile_name,
        signers as _profile_signers, software_role as _profile_role, ioc_names as _profile_iocs
    | dedup _profile_name'''

def cortex_health():
    return '''dataset = rmm_tool_profiles
    | filter release in (dataset = rmm_tool_profiles | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
    | comp count() as _profile_rows, count_distinct(process_name) as _profile_keys,
        count_distinct(release_digest) as _profile_digests,
        sum(if(record_type = "manifest", 1, 0)) as _profile_markers,
        max(to_integer(expected_rows)) as _expected_rows, max(release) as ProfileVersion
    | alter ProfileOK = if(_profile_rows = add(_expected_rows, 1) and _profile_keys = add(_expected_rows, 1)
        and _expected_rows > 0 and _profile_markers = 1 and _profile_digests = 1, true, false)
    | alter ReportStatus = if(ProfileOK = true, "ok", "profile_data_unavailable"), _health_key = 1'''

def mde_definitions(inline=False):
    return '''let ProfileRaw=materialize('''+mde_source(inline)+''');
let ProfileMarker=materialize(ProfileRaw | where record_type == "manifest" | top 1 by release desc);
let ProfileRelease=toscalar(ProfileMarker | project release);
let ProfileRows=materialize(ProfileRaw | where record_type == "profile" and release == ProfileRelease);
let ProfileOK=toscalar(ProfileRows | summarize n=count()) == toscalar(ProfileMarker | project tolong(expected_rows))
    and toscalar(ProfileRows | summarize by process_name | count) == toscalar(ProfileRows | count)
    and toscalar(ProfileRows | summarize by release_digest | count) == 1
    and toscalar(ProfileRows | take 1 | project release_digest) == toscalar(ProfileMarker | project release_digest)
    and toscalar(ProfileRows | summarize n=count()) > 0;
let Profiles=materialize(ProfileRows | where ProfileOK | project ProfileName=process_name, ProfileTool=tool_name, ProfileId=tool_id,
    ProfileSigners=signers, ProfileRole=software_role, ProfileIocNames=ioc_names);
'''

def mde_identity():
    return '''| extend RuleOriginal=tolower(InitiatingProcessVersionInfoOriginalFileName)
| join kind=leftouter Profiles on $left.RuleName == $right.ProfileName
| join kind=leftouter (Profiles | project OriginalName=ProfileName, OriginalTool=ProfileTool, OriginalId=ProfileId,
    OriginalSigners=ProfileSigners, OriginalRole=ProfileRole, OriginalIocNames=ProfileIocNames) on $left.RuleOriginal == $right.OriginalName
| extend DetectedTool=coalesce(ProfileTool, OriginalTool), DetectedToolId=coalesce(ProfileId, OriginalId),
    SoftwareRole=coalesce(ProfileRole, OriginalRole), ExpectedSigners=coalesce(ProfileSigners, OriginalSigners),
    IdentityIocNames=coalesce(ProfileIocNames, OriginalIocNames),
    IdentityConflict=isnotempty(ProfileId) and isnotempty(OriginalId) and ProfileId != OriginalId,
    IdentityBasis=case(isnotempty(ProfileName), "file_name", isnotempty(OriginalName), "original_filename", "")
| extend EvidenceLevel=case(IdentityConflict, "evidence_conflict", isempty(DetectedToolId), "domain_only",
    RuleEvidenceValid == true and isnotempty(RuleEvidenceSigner) and ExpectedSigners contains_cs strcat(";", RuleEvidenceSigner, ";")
    and SoftwareRole != "dual_use", "supported_identity", "software_candidate")
| extend ProfileVersion=ProfileRelease, ReportStatus=iff(ProfileOK, "ok", "profile_data_unavailable")
'''

def cortex_identity(inline=False):
    if inline:
        profiles=[r for r in identity.rows() if r['record_type']=='profile']
        result=[]
        for target,field in [('DetectedTool','tool_name'),('DetectedToolId','tool_id'),('SoftwareRole','software_role'),('ExpectedSigners','signers'),('IdentityIocNames','ioc_names')]:
            expr='""'
            for p in reversed(profiles): expr=f'if(_rule_name = {rr.quote(p["process_name"],"cortex")}, {rr.quote(p[field],"cortex")}, {expr})'
            result.append(target+' = '+expr)
        join='| alter '+',\n'.join(result)+'\n| alter ProfileVersion = '+rr.quote(identity.rows()[-1]['release'])+', ReportStatus="ok"\n'
    else:
        join='''| alter _health_key = 1
| join type = left conflict_strategy = left (
    '''+cortex_health()+'''
) as health _health_key = health._health_key
| join type = left conflict_strategy = left (
    '''+profile_query()+'''
) as profile _rule_name = profile._profile_name
| alter DetectedTool=coalesce(_profile_tool, ""), DetectedToolId=coalesce(_profile_id, ""),
    SoftwareRole=coalesce(_profile_role, ""), ExpectedSigners=coalesce(_profile_signers, ""),
    IdentityIocNames=coalesce(_profile_iocs, "")
'''
    return join+'''| alter IdentityBasis=if(DetectedToolId != "", "file_name", ""), IdentityConflict=false,
    EvidenceLevel=if(DetectedToolId = "", "domain_only", if(_signature_valid = true and _rule_signer != ""
        and ExpectedSigners contains concat(";", _rule_signer, ";") and SoftwareRole != "dual_use" and ReportStatus = "ok", "supported_identity", "software_candidate"))
'''

def policy_adjustment(platform):
    native,cond,eq=('extend','iff','==') if platform=='mde' else ('alter','if','=')
    return f'''| {native} NoiseConflict = {cond}(DetectedToolId != "" and DefaultRuleIds != "" and not(DefaultRuleIds contains "rpt-manageengine-endpointcentral"), true, false)
| {native} ActivityDecision={cond}(CustomerActivityRuleIds != "", "excluded", {cond}(NoiseConflict, "retained", ActivityDecision)),
    EvidenceLevel={cond}(NoiseConflict or IdentityConflict, "evidence_conflict", EvidenceLevel)
| {native} DispositionReason={cond}(CustomerActivityRuleIds != "", "customer_whitelist", {cond}(NoiseConflict, "identity_noise_conflict",
    {cond}(ActivityDecision {eq} "excluded" and DefaultRuleIds contains "rpt-manageengine-endpointcentral", "report_scope_exclusion",
    {cond}(ActivityDecision {eq} "excluded" and DefaultRuleIds contains "rpt-browser-standard", "browser_report_scope",
    {cond}(ActivityDecision {eq} "excluded", "known_noise", "retained")))))
'''

EXTRA='DetectedTool, DetectedToolId, SoftwareRole, IdentityBasis, IdentityIocNames, EvidenceLevel, ProfileVersion, ReportStatus, DispositionReason'

def build(base,platform,*,inline=False,view='all'):
    """Enrich before aggregation; every profile name is unique in a release."""
    if platform=='mde':
        base=base.replace('let Network = materialize(',mde_definitions(inline)+'let Network = materialize(',1)
        base=base.replace('InitiatingProcessVersionInfoProductName\n','InitiatingProcessVersionInfoProductName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessUniqueId, InitiatingProcessCreationTime\n',1)
        base=base.replace('CompanyNames=make_set(', 'OriginalFileNames=make_set(InitiatingProcessVersionInfoOriginalFileName), ProcessUniqueIds=make_set(InitiatingProcessUniqueId), ProcessCreationTimes=make_set(InitiatingProcessCreationTime),\n                CompanyNames=make_set(',1)
        base=base.replace('AccountNames, AccountDomains, CompanyNames, ProductNames,','OriginalFileNames, ProcessUniqueIds, ProcessCreationTimes, AccountNames, AccountDomains, CompanyNames, ProductNames,',1)
        base=base.replace('ProcessIds, RemoteURLs, RemoteIPs,','OriginalFileNames, ProcessUniqueIds, ProcessCreationTimes, ProcessIds, RemoteURLs, RemoteIPs,',1)
        # Every dependency is in an earlier extend stage.
        anchor='| extend DefaultRuleIds ='
        base=base.replace(anchor,mde_identity()+anchor,1)
        category='| extend ReviewCategory ='
        base=base.replace(category,policy_adjustment(platform)+category,1)
        base=base.replace('ReviewCategory, ActivityDecision, DefaultRuleIds',EXTRA+', ReviewCategory, ActivityDecision, DefaultRuleIds')
        base=base.replace('| project DeviceNames, DeviceId, ReviewCategory,','| project DeviceNames, DeviceId, '+EXTRA+', ReviewCategory,')
        base=base.replace('| extend IOCRelatedTools=RMMTools, MatchBasis="domain"','| extend IOCRelatedTools=RMMTools, MatchBasis=iff(DetectedToolId != "", "domain+identity", "domain")')
        # Health rows remain visible even if the selected time range has no events.
        base=base.replace('| order by LastSeen desc','| union (print ReportStatus=iff(ProfileOK, "ok", "profile_data_unavailable"), ProfileVersion=ProfileRelease | where ReportStatus != "ok")\n| order by LastSeen desc')
    else:
        base=base.replace('| alter DefaultRuleIds =',cortex_identity(inline)+'| alter DefaultRuleIds =',1)
        base=base.replace('| alter ReviewCategory =',policy_adjustment(platform)+'| alter ReviewCategory =',1)
        base=base.replace('ReviewCategory, ActivityDecision, DefaultRuleIds',EXTRA+', ReviewCategory, ActivityDecision, DefaultRuleIds')
        base=base.replace('| fields agent_hostname, agent_id, ReviewCategory,','| fields agent_hostname, agent_id, '+EXTRA+', ReviewCategory,')
        base=base.replace('match_basis = "domain",','match_basis = if(DetectedToolId != "", "domain+identity", "domain"),')
        if not inline:
            base=base.replace('| sort desc last_seen', '| union ('+cortex_health()+'\n| filter ReportStatus != "ok" | fields ReportStatus, ProfileVersion)\n| sort desc last_seen')
    sort='| order by LastSeen desc' if platform=='mde' else '| sort desc last_seen'
    main_condition='EvidenceLevel '+('==' if platform=='mde' else '=')+' "supported_identity" and SoftwareRole '+('==' if platform=='mde' else '=')+' "rmm"'
    native,cond=('extend','iff') if platform=='mde' else ('alter','if')
    base=base.replace(sort,f'| {native} ReportSection={cond}(ReportStatus != "ok", "data_error", {cond}({main_condition}, "main", "review"))\n'+sort)
    if view!='all':
        filt='where' if platform=='mde' else 'filter'
        # Candidates remain visible; only supported identities are in the main view.
        condition='ReportSection '+('==' if platform=='mde' else '=')+' '+rr.quote(view)
        base=base.replace(sort,'| '+filt+' ReportStatus != "ok" or '+condition+'\n'+sort)
    if platform=='cortex':
        # XQL union lowercases shared column names; use stable lowercase names.
        base=base.replace('ReportStatus','report_status').replace('ProfileVersion','profile_version')
    return base.replace('// Generated by scripts/build_rmm_queries.py;', '// Identity data '+('inline' if inline else 'external')+'; generated by scripts/build_rmm_queries.py;',1)


def process_query(base, platform, *, inline=False, view='all'):
    """Reuse event-level policy and certificate logic for the newly created process."""
    query = build(base, platform, inline=inline, view=view)
    if platform == 'mde':
        start = query.index('    DeviceNetworkEvents\n')
        end = query.index('\n);\nlet CandidateHashes', start)
        query = query[:start] + '''    DeviceProcessEvents
    | where Timestamp between (ReportStart .. ReportEnd)
    | where ActionType == "ProcessCreated"
    | where FileName in~ (Profiles | project ProfileName) or ProcessVersionInfoOriginalFileName in~ (Profiles | project ProfileName)
    | project Timestamp, DeviceId, DeviceName, RemoteUrl="", RemoteHost="", RemoteIP="", RemotePort=int(null), LocalIP="",
        InitiatingProcessFileName=FileName, InitiatingProcessFolderPath=FolderPath,
        InitiatingProcessSHA1=SHA1, InitiatingProcessSHA256=SHA256, InitiatingProcessCommandLine=ProcessCommandLine,
        InitiatingProcessAccountName=AccountName, InitiatingProcessAccountDomain=AccountDomain,
        InitiatingProcessParentFileName=InitiatingProcessFileName, InitiatingProcessParentId=InitiatingProcessId,
        InitiatingProcessId=ProcessId, InitiatingProcessVersionInfoCompanyName=ProcessVersionInfoCompanyName,
        InitiatingProcessVersionInfoProductName=ProcessVersionInfoProductName,
        InitiatingProcessVersionInfoOriginalFileName=ProcessVersionInfoOriginalFileName,
        InitiatingProcessUniqueId=ProcessUniqueId, InitiatingProcessCreationTime=ProcessCreationTime''' + query[end:]
        start = query.index('    | extend Labels=')
        end = query.index('| project DeviceNames, DeviceId,', start)
        query = query[:start] + ''';
Activities
| extend IOCRelatedTools=dynamic([]), RMMTools=dynamic([]), MatchedDomains=dynamic([]), SourcePatterns=dynamic([]),
    MatchBasis="process_execution", AssociationDecision="not_applicable", CustomerAssociationRuleIds=dynamic([])
''' + query[end:]
        # Export child fields explicitly; do not label these as initiating/parent fields.
        query = query.replace('| order by LastSeen desc', '''| project-rename ProcessFileName=InitiatingProcessFileName, ProcessFolderPath=InitiatingProcessFolderPath,
    ProcessSHA1=InitiatingProcessSHA1, ProcessSHA256=InitiatingProcessSHA256, ProcessExecutionCount=EventCount
| order by LastSeen desc''')
    else:
        names=', '.join(rr.quote(p['process_name'],'cortex') for p in identity.rows() if p['record_type']=='profile')
        candidates = '('+names+')' if inline else '('+profile_query()+' | fields _profile_name)'
        query = query.replace('| filter action_external_hostname != null or action_remote_ip != null', '''| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter lowercase(action_process_image_name) in '''+candidates+'''
| alter actor_process_image_name=action_process_image_name, actor_process_image_path=action_process_image_path,
    actor_process_image_sha256=action_process_image_sha256, actor_process_command_line=action_process_image_command_line,
    actor_process_signature_status=action_process_signature_status, actor_process_signature_vendor=action_process_signature_vendor,
    actor_process_signature_product="", actor_process_instance_id=action_process_instance_id,
    actor_process_os_pid=action_process_os_pid, action_external_hostname="", action_remote_ip="", action_local_ip="", action_remote_port=null''',1)
        query = query.replace('| filter remote_host != ""\n','',1)
        start = query.index('| alter _time = first_seen,')
        end = query.index('| fields agent_hostname, agent_id,', start)
        query = query[:start]+'''| alter ioc_related_tools=null, rmm_tools=null, matched_domains=null, patterns=null,
    match_basis="process_execution", signature_evidence_source="action_process_event",
    AssociationDecision="not_applicable", CustomerAssociationRuleIds=""
'''+query[end:]
        # user fields belong to the initiating actor; retain that provenance.
        query = query.replace('| sort desc last_seen','''| alter process_name=actor_process_image_name, process_path=actor_process_image_path,
    process_sha256=actor_process_image_sha256, process_execution_count=event_count,
    initiating_usernames=usernames, initiating_effective_usernames=effective_usernames
| fields - actor_process_image_name, actor_process_image_path, actor_process_image_sha256, event_count, usernames, effective_usernames
| sort desc last_seen''')
    query=re.sub(r'(?m)^(\s*\|\s*(?:extend|alter)\s+)ReviewCategory =.*$',r'\1ReviewCategory = "process_execution"',query)
    return '// Process creation inventory; counts executions, not remote sessions or installed software.\n'+query
