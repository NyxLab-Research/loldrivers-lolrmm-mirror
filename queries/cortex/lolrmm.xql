// RMM-related domain connections; general/customer rules are lookup data. See README.md.
config case_sensitive = true timeframe = 7d
| dataset = xdr_data
| filter event_type = ENUM.NETWORK and ((action_external_hostname != null and action_external_hostname != "") or action_remote_ip != null)
| fields _time,agent_hostname,agent_id,actor_process_image_name,actor_process_image_path,actor_process_image_sha256,actor_primary_username,action_external_hostname,action_remote_ip
| alter DeviceName = agent_hostname,DeviceId = agent_id,ProcessName = coalesce(actor_process_image_name,""),ProcessPath = coalesce(actor_process_image_path,""),
    SHA256 = lowercase(coalesce(actor_process_image_sha256,"")),User = coalesce(actor_primary_username,""),
    RemoteHost = lowercase(rtrim(if(action_external_hostname != null and action_external_hostname != "",action_external_hostname,coalesce(to_string(action_remote_ip),"")),".")),RemoteIP = coalesce(to_string(action_remote_ip),"")
| alter _DomainKey = arraycreate(if(array_length(split(RemoteHost,".")) > 1,concat("suffix:",arrayindex(split(RemoteHost,"."),-2),".",arrayindex(split(RemoteHost,"."),-1)),concat("unused:",RemoteHost)),concat("single:",arrayindex(split(RemoteHost,"."),-1)))
| arrayexpand _DomainKey
| filter _DomainKey in (dataset = lolrmm_domains | alter _DomainKey = if(array_length(split(domain,".")) > 1,concat("suffix:",arrayindex(split(domain,"."),-2),".",arrayindex(split(domain,"."),-1)),concat("single:",domain)) | fields domain,rmm_tool,pattern,_DomainKey | fields _DomainKey)
| comp min(_time) as FirstSeen,max(_time) as LastSeen,count() as EventCount by DeviceName,DeviceId,ProcessName,ProcessPath,SHA256,User,RemoteHost,RemoteIP,_DomainKey
| join type = inner (dataset = lolrmm_domains | alter _DomainKey = if(array_length(split(domain,".")) > 1,concat("suffix:",arrayindex(split(domain,"."),-2),".",arrayindex(split(domain,"."),-1)),concat("single:",domain)) | fields domain,rmm_tool,pattern,_DomainKey) as D _DomainKey = D._DomainKey
| filter ((array_length(split(pattern,"*")) = 1 and RemoteHost = pattern) or (array_length(split(pattern,"*")) = 2 and len(RemoteHost) >= add(len(arrayindex(split(pattern,"*"),0)),len(arrayindex(split(pattern,"*"),1))) and (arrayindex(split(pattern,"*"),0) = "" or (RemoteHost contains arrayindex(split(pattern,"*"),0) and arrayindex(split(RemoteHost,arrayindex(split(pattern,"*"),0)),0) = "")) and (arrayindex(split(pattern,"*"),1) = "" or (RemoteHost contains arrayindex(split(pattern,"*"),1) and arrayindex(split(RemoteHost,arrayindex(split(pattern,"*"),1)),-1) = ""))))
| comp min(FirstSeen) as FirstSeen,max(LastSeen) as LastSeen,max(EventCount) as EventCount by DeviceName,DeviceId,ProcessName,ProcessPath,SHA256,User,RemoteHost,RemoteIP,domain,rmm_tool
| alter Software = rmm_tool,MatchedDomain = domain,RuleName = lowercase(ProcessName),RulePath = if(ProcessPath ~= "^[A-Za-z]:",lowercase(replex(ProcessPath,"[\\\\]","/")),ProcessPath)
| alter _Record = to_json_string(arraycreate(DeviceName,DeviceId,Software,ProcessName,ProcessPath,User,SHA256,RemoteHost,RemoteIP,MatchedDomain)),
    _PolicyKey = arraycreate(concat("name:",RuleName),concat("tool:",lowercase(Software)),"*")
| arrayexpand _PolicyKey
| join type = left (dataset = rmm_general_rules
 | filter release in (dataset = rmm_general_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | union (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release))
 | filter record_type = "condition"
 | filter expires_at = "" or current_time() < parse_timestamp("%Y-%m-%dT%H:%M:%SZ",expires_at)
 | filter rule_kind != "general" or rule_id not in (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release) | filter record_type = "disabled" | fields rule_id)) as R _PolicyKey = R.anchor_key
| alter _Actual = if(field_name = "device_id",DeviceId,field_name = "device_name",lowercase(DeviceName),field_name = "process_name",RuleName,field_name = "process_path",RulePath,field_name = "sha256",SHA256,field_name = "remote_host",RemoteHost,field_name = "matched_domain",MatchedDomain,field_name = "rmm_tool",lowercase(Software),""),_Value = value
| alter _Condition = if(_Actual != null and _Actual != "" and (
    ((operator = "equals" or operator = "exact") and _Actual = _Value)
    or (operator = "contains" and _Actual contains _Value)
    or (operator = "path_prefix" and _Actual contains _Value and arrayindex(split(_Actual,_Value),0) = "")
    or (operator = "domain_suffix" and (_Actual = _Value or (_Actual contains concat(".",_Value) and arrayindex(split(_Actual,concat(".",_Value)),-1) = "")))
    or (operator = "glob" and ((array_length(split(_Value,"*")) = 1 and _Actual = _Value) or (array_length(split(_Value,"*")) = 2 and len(_Actual) >= add(len(arrayindex(split(_Value,"*"),0)),len(arrayindex(split(_Value,"*"),1))) and (arrayindex(split(_Value,"*"),0) = "" or (_Actual contains arrayindex(split(_Value,"*"),0) and arrayindex(split(_Actual,arrayindex(split(_Value,"*"),0)),0) = "")) and (arrayindex(split(_Value,"*"),1) = "" or (_Actual contains arrayindex(split(_Value,"*"),1) and arrayindex(split(_Actual,arrayindex(split(_Value,"*"),1)),-1) = "")))))),condition_id,null)
| comp count_distinct(_Condition) as Matched,max(to_integer(condition_count)) as Required by _Record,FirstSeen,LastSeen,EventCount,rule_id,rule_kind,group_id
| alter GroupHit = if(Matched = Required and Required > 0,1,0)
| comp max(if(rule_kind = "general",GroupHit,0)) as GeneralHit,max(if(rule_kind = "retain",GroupHit,0)) as RetainHit,
    max(if(rule_kind = "customer" or rule_kind = "general_whitelist",GroupHit,0)) as WhitelistHit by _Record,FirstSeen,LastSeen,EventCount
| filter (GeneralHit = 0 or RetainHit = 1) and WhitelistHit = 0
| alter DeviceName = json_extract_scalar(_Record,"$[0]"),DeviceId = json_extract_scalar(_Record,"$[1]"),Software = json_extract_scalar(_Record,"$[2]"),ProcessName = json_extract_scalar(_Record,"$[3]"),ProcessPath = json_extract_scalar(_Record,"$[4]"),User = json_extract_scalar(_Record,"$[5]"),SHA256 = json_extract_scalar(_Record,"$[6]"),RemoteHost = json_extract_scalar(_Record,"$[7]"),RemoteIP = json_extract_scalar(_Record,"$[8]"),MatchedDomain = json_extract_scalar(_Record,"$[9]")
| alter _Context = to_json_string(arraycreate(DeviceName,DeviceId,Software,ProcessName,ProcessPath,User,SHA256,RemoteHost,RemoteIP))
| comp min(FirstSeen) as FirstSeen,max(LastSeen) as LastSeen,max(EventCount) as EventCount,values(MatchedDomain) as _Domains by _Context,DeviceId,Software,RemoteHost,RemoteIP
| windowcomp first_value(_Context) by DeviceId,Software sort desc LastSeen,asc _Context between null and null as _Latest
| alter _FirstDomain = arrayindex(_Domains,0)
| arrayexpand _Domains
| alter _Contribution = if(_Domains = _FirstDomain,EventCount,0)
| comp min(FirstSeen) as FirstSeen,max(LastSeen) as LastSeen,sum(_Contribution) as EventCount,values(RemoteHost) as RemoteHosts,
    values(if(RemoteIP = "",null,RemoteIP)) as RemoteIPs,values(_Domains) as MatchedDomains,first(_Latest) as _Context by DeviceId,Software
| alter DeviceName = json_extract_scalar(_Context,"$[0]"),DeviceId = json_extract_scalar(_Context,"$[1]"),Software = json_extract_scalar(_Context,"$[2]"),ProcessName = json_extract_scalar(_Context,"$[3]"),ProcessPath = json_extract_scalar(_Context,"$[4]"),User = json_extract_scalar(_Context,"$[5]"),SHA256 = json_extract_scalar(_Context,"$[6]"),RemoteHost = json_extract_scalar(_Context,"$[7]"),RemoteIP = json_extract_scalar(_Context,"$[8]")
| alter _HealthKey = 1
| join type = inner (dataset = rmm_general_rules
 | filter release in (dataset = rmm_general_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | comp count() as Rows,count_distinct(row_id) as Keys,count_distinct(release_digest) as Digests,
     sum(if(record_type = "manifest",1,0)) as Markers,max(to_integer(expected_rows)) as Expected
 | alter OK = if(Rows = add(Expected,1) and Rows = Keys and Digests = 1 and Markers = 1,true,false)
 | fields OK
 | union (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | comp count() as Rows,count_distinct(row_id) as Keys,count_distinct(release_digest) as Digests,
     sum(if(record_type = "manifest",1,0)) as Markers,max(to_integer(expected_rows)) as Expected
 | alter OK = if(Rows = add(Expected,1) and Rows = Keys and Digests = 1 and Markers = 1,true,false)
 | fields OK
 | union (dataset = lolrmm_domains | comp count() as Rows | alter OK = if(Rows > 0,true,false) | fields OK
 | union (dataset = rmm_general_rules
 | filter release in (dataset = rmm_general_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | union (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release))
 | filter record_type = "condition"
 | filter expires_at = "" or current_time() < parse_timestamp("%Y-%m-%dT%H:%M:%SZ",expires_at)
 | filter rule_kind != "general" or rule_id not in (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release) | filter record_type = "disabled" | fields rule_id)
 | comp sum(if(field_name in ("device_id","device_name","matched_domain","process_name","process_path","remote_host","rmm_tool","sha256") and operator in ("contains","domain_suffix","equals","exact","glob","path_prefix"),0,1)) as Bad | alter OK = if(coalesce(Bad,0) = 0,true,false) | fields OK)))
 | comp count() as Checks,sum(if(OK = true,1,0)) as Passed
 | alter ReferencesOK = if(Checks = 4 and Passed = 4,true,false),_HealthKey = 1
 | alter ReportStatus = if(ReferencesOK = true,"ok","reference_or_policy_unavailable")
 | fields _HealthKey,ReferencesOK,ReportStatus) as H _HealthKey = H._HealthKey
| filter ReferencesOK = true
| alter ReportStatus = "ok"
| fields DeviceName,Software,LastSeen,FirstSeen,RemoteHosts,RemoteIPs,MatchedDomains,ProcessName,ProcessPath,User,SHA256,EventCount,ReportStatus
| union (dataset = rmm_general_rules
 | filter release in (dataset = rmm_general_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | comp count() as Rows,count_distinct(row_id) as Keys,count_distinct(release_digest) as Digests,
     sum(if(record_type = "manifest",1,0)) as Markers,max(to_integer(expected_rows)) as Expected
 | alter OK = if(Rows = add(Expected,1) and Rows = Keys and Digests = 1 and Markers = 1,true,false)
 | fields OK
 | union (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | comp count() as Rows,count_distinct(row_id) as Keys,count_distinct(release_digest) as Digests,
     sum(if(record_type = "manifest",1,0)) as Markers,max(to_integer(expected_rows)) as Expected
 | alter OK = if(Rows = add(Expected,1) and Rows = Keys and Digests = 1 and Markers = 1,true,false)
 | fields OK
 | union (dataset = lolrmm_domains | comp count() as Rows | alter OK = if(Rows > 0,true,false) | fields OK
 | union (dataset = rmm_general_rules
 | filter release in (dataset = rmm_general_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | union (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release))
 | filter record_type = "condition"
 | filter expires_at = "" or current_time() < parse_timestamp("%Y-%m-%dT%H:%M:%SZ",expires_at)
 | filter rule_kind != "general" or rule_id not in (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release) | filter record_type = "disabled" | fields rule_id)
 | comp sum(if(field_name in ("device_id","device_name","matched_domain","process_name","process_path","remote_host","rmm_tool","sha256") and operator in ("contains","domain_suffix","equals","exact","glob","path_prefix"),0,1)) as Bad | alter OK = if(coalesce(Bad,0) = 0,true,false) | fields OK)))
 | comp count() as Checks,sum(if(OK = true,1,0)) as Passed
 | alter ReferencesOK = if(Checks = 4 and Passed = 4,true,false),_HealthKey = 1
 | alter ReportStatus = if(ReferencesOK = true,"ok","reference_or_policy_unavailable")
 | fields _HealthKey,ReferencesOK,ReportStatus | filter ReportStatus != "ok" | fields ReportStatus)
| sort desc LastSeen
| fields DeviceName,Software,LastSeen,FirstSeen,RemoteHosts,RemoteIPs,MatchedDomains,ProcessName,ProcessPath,User,SHA256,EventCount,ReportStatus
