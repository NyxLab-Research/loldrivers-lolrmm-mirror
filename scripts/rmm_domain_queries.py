"""Domain-only reporting. Indicator and whitelist values remain external data."""
import json
import re
import rmm_domain_policy as policy
import rmm_reference_data as ref
from rmm_native_queries import cortex_glob, cortex_suffix, health_mde, cortex_active

BASE = 'https://raw.githubusercontent.com/NyxLab-Research/loldrivers-lolrmm-mirror/main/data/'
REPORT_FIELDS = ['DeviceName', 'Software', 'LastSeen', 'FirstSeen', 'RemoteHosts', 'RemoteIPs',
                 'MatchedDomains', 'ProcessName', 'ProcessPath', 'User', 'SHA256', 'EventCount', 'ReportStatus']
CONTEXT_FIELDS = ['DeviceName', 'DeviceId', 'Software', 'LastSeen', 'FirstSeen', 'RemoteHost', 'RemoteIP',
                  'MatchedDomain', 'ProcessName', 'ProcessPath', 'User', 'SHA1', 'SHA256', 'EventCount',
                  'GeneralRuleIds', 'GeneralWhitelistIds', 'GeneralRelease', 'ReportStatus']
OUTPUT_MARKER = '// OUTPUT: replaced by the private MDE customer adapter before aggregation.\n'
EXPRESSIONS = {'device_id': 'DeviceId', 'device_name': 'tolower(DeviceName)', 'process_name': 'RuleName',
               'process_path': 'RulePath', 'sha1': 'SHA1', 'sha256': 'SHA256', 'remote_host': 'RemoteHost',
               'matched_domain': 'MatchedDomain', 'rmm_tool': 'tolower(Software)'}


def timeframe(value):
    if not re.fullmatch(r'[1-9][0-9]*[mhd]', value): raise ValueError('Invalid timeframe')
    policy.domain_rows()
    return value


def mde_control():
    return '(print ReportStatus=iff(ReferencesOK,"ok","reference_or_policy_unavailable") | where ReportStatus!="ok")'


def mde_context_output():
    return ('Contexts | where ReferencesOK | extend GeneralRelease=GeneralRelease,ReportStatus="ok"\n'
            ' | project ' + ','.join(CONTEXT_FIELDS) + '\n | union ' + mde_control() + '\n')


def build_mde(time='7d', contexts=False):
    q='// RMM-related domain connections; general rules are external data. See README.md.\n'
    q+='let ReportStart=ago('+timeframe(time)+');\nlet ReportEnd=now();\n'
    q+='let Domains=materialize(externaldata(Domain:string,Software:string,Pattern:string,Regex:string)\n'
    q+=" [h'"+BASE+"lolrmm_domains.csv'] with(format='csv',ignoreFirstRecord=true)\n"
    q+=' | extend Domain=tolower(Domain),Pattern=tolower(Pattern) | distinct Domain,Software,Pattern);\n'
    q+=('let GeneralRaw=materialize(externaldata('+','.join(k+':string' for k in ref.POLICY_FIELDS)+
        ")[h'"+BASE+"rmm_general_rules.csv'] with(format='csv',ignoreFirstRecord=true));\n")
    q+=health_mde('General','condition',0)
    q=q.replace('let GeneralOK=', 'let GeneralOK=toscalar(GeneralActive | where record_type=="manifest" | count)==1 and ')
    q+='let Rules=materialize(GeneralActive | where record_type=="condition" | where isempty(expires_at) or now()<todatetime(expires_at));\n'
    q+='let ReferencesOK=GeneralOK and toscalar(Domains | count)>0 and toscalar(Rules | where field_name !in ('+','.join(json.dumps(k) for k in sorted(policy.FIELDS))+') or operator !in ('+','.join(json.dumps(k) for k in sorted(policy.OPERATORS-{'in'}))+') | count)==0;\n'
    q+='''let DomainTerms=toscalar(Domains | extend Term=extract(@"[a-z0-9]{3,}",0,Domain) | summarize make_set(Term));
let DomainScan=toscalar(Domains | where isempty(extract(@"[a-z0-9]{3,}",0,Domain)) or not(Domain matches regex @"^[a-z0-9.-]+$") | count)>0 or array_length(DomainTerms)>480;
let Terms0=array_slice(DomainTerms,0,119),Terms1=array_slice(DomainTerms,120,239),Terms2=array_slice(DomainTerms,240,359),Terms3=array_slice(DomainTerms,360,479);
let DomainIndex=Domains | extend Labels=split(Domain,".") | extend DomainKey=iff(array_length(Labels)>1,strcat("suffix:",tostring(Labels[-2]),".",tostring(Labels[-1])),strcat("single:",Domain));
let Raw=materialize(DeviceNetworkEvents
 | where Timestamp>=ReportStart and Timestamp<ReportEnd and ActionType=="ConnectionSuccess"
 | where DomainScan or RemoteUrl has_any(Terms0) or RemoteUrl has_any(Terms1) or RemoteUrl has_any(Terms2) or RemoteUrl has_any(Terms3)
     or RemoteIP has_any(Terms0) or RemoteIP has_any(Terms1) or RemoteIP has_any(Terms2) or RemoteIP has_any(Terms3)
 | project Timestamp,DeviceName,DeviceId,ProcessName=InitiatingProcessFileName,ProcessPath=InitiatingProcessFolderPath,
     User=InitiatingProcessAccountName,SHA1=tolower(InitiatingProcessSHA1),SHA256=tolower(InitiatingProcessSHA256),RemoteUrl,RemoteIP
 | extend RemoteHost=tolower(trim_end(@"[.]+",tostring(parse_url(case(isempty(RemoteUrl),strcat("https://",RemoteIP),RemoteUrl contains "://",RemoteUrl,strcat("https://",RemoteUrl))).Host)))
 | where isnotempty(RemoteHost)
 | extend Labels=split(RemoteHost,".")
 | extend DomainKey=pack_array(iff(array_length(Labels)>1,strcat("suffix:",tostring(Labels[-2]),".",tostring(Labels[-1])),strcat("unused:",RemoteHost)),strcat("single:",tostring(Labels[-1])))
 | mv-expand DomainKey to typeof(string)
 | where DomainKey in (DomainIndex | project DomainKey)
 | lookup kind=inner DomainIndex on DomainKey
 | extend Parts=split(Pattern,"*")
 | where (array_length(Parts)==1 and RemoteHost==Pattern)
     or (array_length(Parts)==2 and RemoteHost startswith_cs tostring(Parts[0]) and RemoteHost endswith_cs tostring(Parts[1]) and strlen(RemoteHost)>=strlen(tostring(Parts[0]))+strlen(tostring(Parts[1])))
 | summarize FirstSeen=min(Timestamp),LastSeen=max(Timestamp),EventCount=count() by DeviceName,DeviceId,Software,ProcessName,ProcessPath,User,SHA1,SHA256,RemoteHost,RemoteIP,MatchedDomain=Domain,Pattern
 | summarize FirstSeen=min(FirstSeen),LastSeen=max(LastSeen),EventCount=max(EventCount) by DeviceName,DeviceId,Software,ProcessName,ProcessPath,User,SHA1,SHA256,RemoteHost,RemoteIP,MatchedDomain
 | extend RuleName=tolower(ProcessName),RulePath=iff(ProcessPath matches regex @"^[A-Za-z]:",tolower(replace_string(ProcessPath,"\\\\","/")),ProcessPath)
 | extend ContextId=tostring(pack_array(DeviceId,Software,ProcessName,ProcessPath,User,SHA1,SHA256,RemoteHost,RemoteIP,MatchedDomain)));
let Hits=Raw | extend RuleKeys=pack_array(strcat("name:",RuleName),strcat("tool:",tolower(Software)),"*")
 | mv-expand RuleKey=RuleKeys to typeof(string)
 | lookup kind=leftouter Rules on $left.RuleKey==$right.anchor_key
 | extend Actual=case('''+','.join('field_name=='+json.dumps(k)+','+v for k,v in EXPRESSIONS.items())+''',""),Parts=split(value,"*")
 | extend Hit=isnotempty(Actual) and case(operator in ("equals","exact"),Actual==value,
     operator=="contains",Actual contains_cs value,operator=="path_prefix",Actual startswith_cs value,
     operator=="domain_suffix",Actual==value or Actual endswith_cs strcat(".",value),
     operator=="glob",(array_length(Parts)==1 and Actual==value) or (array_length(Parts)==2 and Actual startswith_cs tostring(Parts[0]) and Actual endswith_cs tostring(Parts[1]) and strlen(Actual)>=strlen(tostring(Parts[0]))+strlen(tostring(Parts[1]))),false)
 | summarize Conditions=make_set_if(condition_id,Hit),Required=max(toint(condition_count)) by ContextId,rule_id,rule_kind,group_id
 | where Required>0 and array_length(Conditions)==Required
 | summarize GeneralRuleIds=make_set_if(rule_id,rule_kind=="general"),GeneralWhitelistIds=make_set_if(rule_id,rule_kind=="general_whitelist") by ContextId;
let Contexts=Raw | lookup kind=leftouter Hits on ContextId
 | extend GeneralRuleIds=coalesce(GeneralRuleIds,dynamic([])),GeneralWhitelistIds=coalesce(GeneralWhitelistIds,dynamic([]));
'''
    # Separate let statements avoid depending on multi-binding syntax in Defender.
    q=q.replace('let Terms0=array_slice(DomainTerms,0,119),Terms1=array_slice(DomainTerms,120,239),Terms2=array_slice(DomainTerms,240,359),Terms3=array_slice(DomainTerms,360,479);',
                '\n'.join(f'let Terms{i}=array_slice(DomainTerms,{120*i},{120*i+119});' for i in range(4)))
    q+=OUTPUT_MARKER
    if contexts: return q+mde_context_output()
    q+='''Contexts | where ReferencesOK and array_length(GeneralRuleIds)==0 and array_length(GeneralWhitelistIds)==0
 | summarize FirstSeen=min(FirstSeen),LastSeen=max(LastSeen),EventCount=max(EventCount),Domains=make_set(MatchedDomain) by DeviceName,DeviceId,Software,ProcessName,ProcessPath,User,SHA1,SHA256,RemoteHost,RemoteIP
 | mv-expand MatchedDomain=Domains to typeof(string)
 | summarize FirstSeen=min(FirstSeen),EventCount=max(EventCount),MatchedDomains=make_set(MatchedDomain),arg_max(LastSeen,*) by DeviceId,Software,ProcessName,ProcessPath,User,SHA1,SHA256,RemoteHost,RemoteIP
 | summarize FirstSeen=min(FirstSeen),RemoteHosts=make_set(RemoteHost),RemoteIPs=make_set_if(RemoteIP,isnotempty(RemoteIP)),MatchedDomains=make_set(MatchedDomains),EventCount=sum(EventCount),arg_max(LastSeen,*) by DeviceId,Software
 | mv-expand MatchedDomains
 | mv-expand MatchedDomains to typeof(string)
 | summarize MatchedDomains=make_set(MatchedDomains),arg_max(LastSeen,*) by DeviceId,Software
 | extend ReportStatus="ok"
 | project '''+','.join(REPORT_FIELDS)+'\n | union '+mde_control()+'\n | order by LastSeen desc\n'
    return q


def cortex_health():
    checks=[]
    for kind in ('general','customer'):
        checks.append(cortex_active(kind)+'''
 | comp count() as Rows,count_distinct(row_id) as Keys,count_distinct(release_digest) as Digests,
     sum(if(record_type = "manifest",1,0)) as Markers,max(to_integer(expected_rows)) as Expected
 | alter OK = if(Rows = add(Expected,1) and Rows = Keys and Digests = 1 and Markers = 1,true,false)
 | fields OK''')
    checks.append('dataset = lolrmm_domains | comp count() as Rows | alter OK = if(Rows > 0,true,false) | fields OK')
    rules=cortex_rules()
    checks.append(rules+'\n | comp sum(if(field_name in ('+','.join(json.dumps(k) for k in sorted(policy.FIELDS-{'sha1'}))+') and operator in ('+','.join(json.dumps(k) for k in sorted(policy.OPERATORS-{'in'}))+'),0,1)) as Bad | alter OK = if(coalesce(Bad,0) = 0,true,false) | fields OK')
    return '\n | union ('.join(checks)+')'*(len(checks)-1)+'''
 | comp count() as Checks,sum(if(OK = true,1,0)) as Passed
 | alter ReferencesOK = if(Checks = 4 and Passed = 4,true,false),_HealthKey = 1
 | alter ReportStatus = if(ReferencesOK = true,"ok","reference_or_policy_unavailable")
 | fields _HealthKey,ReferencesOK,ReportStatus'''


def cortex_rules():
    return cortex_active('general')+'\n | union ('+cortex_active('customer')+''')
 | filter record_type = "condition"
 | filter expires_at = "" or current_time() < parse_timestamp("%Y-%m-%dT%H:%M:%SZ",expires_at)
 | filter rule_kind != "general" or rule_id not in ('''+cortex_active('customer')+' | filter record_type = "disabled" | fields rule_id)'


def build_cortex(time='7d'):
    def key(host,source=False):
        labels='split('+host+',".")'
        return 'if(array_length('+labels+') > 1,concat("suffix:",arrayindex('+labels+',-2),".",arrayindex('+labels+',-1)),concat("'+('unused:' if source else 'single:')+'",'+host+'))'
    domains='dataset = lolrmm_domains | alter _DomainKey = '+key('domain')+' | fields domain,rmm_tool,pattern,_DomainKey'
    q='// RMM-related domain connections; general/customer rules are lookup data. See README.md.\n'
    q+='config case_sensitive = true timeframe = '+timeframe(time)+'\n| dataset = xdr_data\n'
    q+='''| filter event_type = ENUM.NETWORK and ((action_external_hostname != null and action_external_hostname != "") or action_remote_ip != null)
| fields _time,agent_hostname,agent_id,actor_process_image_name,actor_process_image_path,actor_process_image_sha256,actor_primary_username,action_external_hostname,action_remote_ip
| alter DeviceName = agent_hostname,DeviceId = agent_id,ProcessName = coalesce(actor_process_image_name,""),ProcessPath = coalesce(actor_process_image_path,""),
    SHA256 = lowercase(coalesce(actor_process_image_sha256,"")),User = coalesce(actor_primary_username,""),
    RemoteHost = lowercase(rtrim(if(action_external_hostname != null and action_external_hostname != "",action_external_hostname,coalesce(to_string(action_remote_ip),"")),".")),RemoteIP = coalesce(to_string(action_remote_ip),"")
| alter _DomainKey = arraycreate('''+key('RemoteHost',True)+''',concat("single:",arrayindex(split(RemoteHost,"."),-1)))
| arrayexpand _DomainKey
| filter _DomainKey in ('''+domains+''' | fields _DomainKey)
| comp min(_time) as FirstSeen,max(_time) as LastSeen,count() as EventCount by DeviceName,DeviceId,ProcessName,ProcessPath,SHA256,User,RemoteHost,RemoteIP,_DomainKey
| join type = inner ('''+domains+''') as D _DomainKey = D._DomainKey
| filter ('''+cortex_glob('RemoteHost')+''')
| comp min(FirstSeen) as FirstSeen,max(LastSeen) as LastSeen,max(EventCount) as EventCount by DeviceName,DeviceId,ProcessName,ProcessPath,SHA256,User,RemoteHost,RemoteIP,domain,rmm_tool
| alter Software = rmm_tool,MatchedDomain = domain,RuleName = lowercase(ProcessName),RulePath = if(ProcessPath ~= "^[A-Za-z]:",lowercase(replex(ProcessPath,"[\\\\\\\\]","/")),ProcessPath)
| alter _Record = to_json_string(arraycreate(DeviceName,DeviceId,Software,ProcessName,ProcessPath,User,SHA256,RemoteHost,RemoteIP,MatchedDomain)),
    _PolicyKey = arraycreate(concat("name:",RuleName),concat("tool:",lowercase(Software)),"*")
| arrayexpand _PolicyKey
| join type = left ('''+cortex_rules()+''') as R _PolicyKey = R.anchor_key
'''
    ex={'device_id':'DeviceId','device_name':'lowercase(DeviceName)','process_name':'RuleName','process_path':'RulePath','sha256':'SHA256','remote_host':'RemoteHost','matched_domain':'MatchedDomain','rmm_tool':'lowercase(Software)'}
    q+='| alter _Actual = if('+','.join('field_name = '+json.dumps(k)+','+v for k,v in ex.items())+',""),_Value = value\n'
    q+='''| alter _Condition = if(_Actual != null and _Actual != "" and (
    ((operator = "equals" or operator = "exact") and _Actual = _Value)
    or (operator = "contains" and _Actual contains _Value)
    or (operator = "path_prefix" and _Actual contains _Value and arrayindex(split(_Actual,_Value),0) = "")
    or (operator = "domain_suffix" and '''+cortex_suffix('_Actual','_Value')+''')
    or (operator = "glob" and ('''+cortex_glob('_Actual','_Value')+'''))),condition_id,null)
| comp count_distinct(_Condition) as Matched,max(to_integer(condition_count)) as Required by _Record,FirstSeen,LastSeen,EventCount,rule_id,rule_kind,group_id
| alter GroupHit = if(Matched = Required and Required > 0,1,0)
| comp max(if(rule_kind = "general",GroupHit,0)) as GeneralHit,max(if(rule_kind = "retain",GroupHit,0)) as RetainHit,
    max(if(rule_kind = "customer" or rule_kind = "general_whitelist",GroupHit,0)) as WhitelistHit by _Record,FirstSeen,LastSeen,EventCount
| filter (GeneralHit = 0 or RetainHit = 1) and WhitelistHit = 0
'''
    names=['DeviceName','DeviceId','Software','ProcessName','ProcessPath','User','SHA256','RemoteHost','RemoteIP','MatchedDomain']
    q+='| alter '+','.join(n+' = json_extract_scalar(_Record,"$['+str(i)+']")' for i,n in enumerate(names))+'\n'
    # Remove duplicate IOC associations before adding event counts; latest tuple stays coherent.
    q+='| alter _Context = to_json_string(arraycreate(DeviceName,DeviceId,Software,ProcessName,ProcessPath,User,SHA256,RemoteHost,RemoteIP))\n'
    q+='''| comp min(FirstSeen) as FirstSeen,max(LastSeen) as LastSeen,max(EventCount) as EventCount,values(MatchedDomain) as _Domains by _Context,DeviceId,Software,RemoteHost,RemoteIP
| windowcomp first_value(_Context) by DeviceId,Software sort desc LastSeen,asc _Context between null and null as _Latest
| alter _FirstDomain = arrayindex(_Domains,0)
| arrayexpand _Domains
| alter _Contribution = if(_Domains = _FirstDomain,EventCount,0)
| comp min(FirstSeen) as FirstSeen,max(LastSeen) as LastSeen,sum(_Contribution) as EventCount,values(RemoteHost) as RemoteHosts,
    values(if(RemoteIP = "",null,RemoteIP)) as RemoteIPs,values(_Domains) as MatchedDomains,first(_Latest) as _Context by DeviceId,Software
'''
    q+='| alter '+','.join(n+' = json_extract_scalar(_Context,"$['+str(i)+']")' for i,n in enumerate(names[:-1]))+'\n'
    health=cortex_health()
    q+='| alter _HealthKey = 1\n| join type = inner ('+health+') as H _HealthKey = H._HealthKey\n| filter ReferencesOK = true\n| alter ReportStatus = "ok"\n'
    q+='| fields '+','.join(REPORT_FIELDS)+'\n| union ('+health+' | filter ReportStatus != "ok" | fields ReportStatus)\n| sort desc LastSeen\n| fields '+','.join(REPORT_FIELDS)+'\n'
    return q
