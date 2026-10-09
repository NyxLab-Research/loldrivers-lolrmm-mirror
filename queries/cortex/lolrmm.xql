// Native RMM activity; source definitions and integration contract: README.md.
config case_sensitive = true timeframe = 7d
| dataset = xdr_data
 | filter event_type = ENUM.NETWORK and ((action_external_hostname != null and action_external_hostname != "") or action_remote_ip != null)
| alter DeviceName = agent_hostname, DeviceId = agent_id,
    ProcessName = if(event_type = ENUM.PROCESS,action_process_image_name,actor_process_image_name),
    ProcessPath = if(event_type = ENUM.PROCESS,action_process_image_path,actor_process_image_path),
    SHA256 = lowercase(coalesce(if(event_type = ENUM.PROCESS,action_process_image_sha256,actor_process_image_sha256),"")),
    Publisher = coalesce(if(event_type = ENUM.PROCESS,action_process_signature_vendor,actor_process_signature_vendor),""),
    SignatureValid = if(if(event_type = ENUM.PROCESS,action_process_signature_status,actor_process_signature_status) = 1,true,false),
    SignatureStatus = if(if(event_type = ENUM.PROCESS,action_process_signature_status,actor_process_signature_status) = 1,"Valid",if(event_type = ENUM.PROCESS,action_process_signature_status,actor_process_signature_status) = 2,"Not valid or not trusted","Unavailable"),
    User = if(event_type = ENUM.PROCESS,"",coalesce(actor_primary_username,"")),
    RemoteHost = if(event_type = ENUM.PROCESS,"",lowercase(rtrim(if(action_external_hostname != null and action_external_hostname != "",action_external_hostname,coalesce(to_string(action_remote_ip),"")),"."))),
    RemoteIP = if(event_type = ENUM.PROCESS,"",coalesce(to_string(action_remote_ip),"")),
    Activity = if(event_type = ENUM.PROCESS,"Process start","Network activity"), SHA1 = ""
| alter RuleName = lowercase(ProcessName), RulePath = if(ProcessPath ~= "^[A-Za-z]:",lowercase(replex(ProcessPath,"[\\\\]","/")),ProcessPath)
| alter _SourceRecord = to_json_string(arraycreate(DeviceName,DeviceId,ProcessName,ProcessPath,Publisher,SHA256,User,RemoteHost,RemoteIP,Activity,SignatureStatus))
| comp min(_time) as FirstObserved,max(_time) as _time,count() as EventCount by _SourceRecord,DeviceName,DeviceId,ProcessName,ProcessPath,SHA256,Publisher,SignatureValid,SignatureStatus,User,RemoteHost,RemoteIP,Activity,SHA1,RuleName,RulePath
| join type = inner (dataset = rmm_discovery_indicators
 | filter release in (dataset = rmm_discovery_indicators | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | filter record_type = "domain" | fields tool_id,tool_name,software_role,domain,pattern) as D RemoteHost = D.domain or wildcard_match(RemoteHost,concat("*.",D.domain))
| filter wildcard_match(RemoteHost,pattern)
| alter ProcessMatch = 0, DomainMatch = 1, MatchedDomain = domain
| union (dataset = xdr_data
 | filter event_type = ENUM.NETWORK or (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START)
| alter DeviceName = agent_hostname, DeviceId = agent_id,
    ProcessName = if(event_type = ENUM.PROCESS,action_process_image_name,actor_process_image_name),
    ProcessPath = if(event_type = ENUM.PROCESS,action_process_image_path,actor_process_image_path),
    SHA256 = lowercase(coalesce(if(event_type = ENUM.PROCESS,action_process_image_sha256,actor_process_image_sha256),"")),
    Publisher = coalesce(if(event_type = ENUM.PROCESS,action_process_signature_vendor,actor_process_signature_vendor),""),
    SignatureValid = if(if(event_type = ENUM.PROCESS,action_process_signature_status,actor_process_signature_status) = 1,true,false),
    SignatureStatus = if(if(event_type = ENUM.PROCESS,action_process_signature_status,actor_process_signature_status) = 1,"Valid",if(event_type = ENUM.PROCESS,action_process_signature_status,actor_process_signature_status) = 2,"Not valid or not trusted","Unavailable"),
    User = if(event_type = ENUM.PROCESS,"",coalesce(actor_primary_username,"")),
    RemoteHost = if(event_type = ENUM.PROCESS,"",lowercase(rtrim(if(action_external_hostname != null and action_external_hostname != "",action_external_hostname,coalesce(to_string(action_remote_ip),"")),"."))),
    RemoteIP = if(event_type = ENUM.PROCESS,"",coalesce(to_string(action_remote_ip),"")),
    Activity = if(event_type = ENUM.PROCESS,"Process start","Network activity"), SHA1 = ""
| alter RuleName = lowercase(ProcessName), RulePath = if(ProcessPath ~= "^[A-Za-z]:",lowercase(replex(ProcessPath,"[\\\\]","/")),ProcessPath)
| alter _IndicatorAnchor = arraycreate(concat("name:",RuleName),concat("prefix:",arrayindex(split(RuleName,"-"),0)),concat("prefix:",arrayindex(split(RuleName,"_"),0)))
| arrayexpand _IndicatorAnchor
| filter _IndicatorAnchor in (dataset = rmm_discovery_indicators | filter record_type = "process" | fields anchor_key)
| alter _SourceRecord = to_json_string(arraycreate(DeviceName,DeviceId,ProcessName,ProcessPath,Publisher,SHA256,User,RemoteHost,RemoteIP,Activity,SignatureStatus))
| comp min(_time) as FirstObserved,max(_time) as _time,count() as EventCount by _SourceRecord,DeviceName,DeviceId,ProcessName,ProcessPath,SHA256,Publisher,SignatureValid,SignatureStatus,User,RemoteHost,RemoteIP,Activity,SHA1,RuleName,RulePath,_IndicatorAnchor
 | join type = inner (dataset = rmm_discovery_indicators
 | filter release in (dataset = rmm_discovery_indicators | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | filter record_type = "process" | fields tool_id,tool_name,software_role,pattern,anchor_key) as I _IndicatorAnchor = I.anchor_key
 | filter wildcard_match(RuleName,pattern)
 | alter ProcessMatch = 1, DomainMatch = 0, MatchedDomain = "")
| comp max(ProcessMatch) as ProcessMatch,max(DomainMatch) as DomainMatch,values(MatchedDomain) as MatchedDomains,max(EventCount) as EventCount
    by _SourceRecord,_time,FirstObserved,DeviceName,DeviceId,ProcessName,ProcessPath,SHA256,Publisher,SignatureValid,SignatureStatus,User,RemoteHost,RemoteIP,Activity,SHA1,RuleName,RulePath,tool_id,tool_name,software_role
| alter SoftwareId = tool_id, Software = tool_name, SoftwareRole = software_role
| fields _time,FirstObserved,EventCount,DeviceName,DeviceId,ProcessName,ProcessPath,SHA256,Publisher,SignatureValid,SignatureStatus,User,RemoteHost,RemoteIP,Activity,SHA1,RuleName,RulePath,SoftwareId,Software,SoftwareRole,ProcessMatch,DomainMatch,MatchedDomains
| join type = left (dataset = rmm_tool_profiles_v2
 | filter release in (dataset = rmm_tool_profiles_v2 | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | filter record_type = "profile" | fields process_name,tool_id,signers,path_prefix,path_contains) as P RuleName = P.process_name
| alter IdentityValid = if(tool_id = SoftwareId and SignatureValid = true and Publisher != "" and signers contains concat(";",lowercase(Publisher),";")
    and (path_prefix = "" or RulePath contains path_prefix and arrayindex(split(RulePath,path_prefix),0) = "")
    and (path_contains = "" or RulePath contains path_contains),true,false),
    EvidenceConflict = if(tool_id = SoftwareId and ((path_prefix != "" and not(RulePath contains path_prefix and arrayindex(split(RulePath,path_prefix),0) = "")) or (path_contains != "" and not(RulePath contains path_contains))),true,false)
| alter Evidence = if(EvidenceConflict = true,"Conflicting file metadata",SoftwareRole = "ambiguous","Ambiguous process name",IdentityValid = true,"Verified process identity",ProcessMatch = 1 and DomainMatch = 1,"Process and domain match",DomainMatch = 1,"Domain match only","Process match only"),
    _MatchedDomainsJSON = to_json_string(MatchedDomains),
    _Record = to_json_string(arraycreate(DeviceName,DeviceId,SoftwareId,Software,ProcessName,ProcessPath,Publisher,SHA256,User,RemoteHost,RemoteIP,SignatureStatus)),
    _PolicyKey = arraycreate(concat("name:",RuleName),concat("tool:",SoftwareId),"*")
| arrayexpand _PolicyKey
| join type = left (dataset = rmm_general_rules
 | filter release in (dataset = rmm_general_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | union (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release))
 | filter record_type = "condition"
 | filter expires_at = "" or current_time() < parse_timestamp("%Y-%m-%dT%H:%M:%SZ", expires_at)
 | filter rule_kind != "general" or rule_id not in (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release) | filter record_type = "disabled" | fields rule_id)) as R _PolicyKey = R.anchor_key
| alter _Actual = if(field_name = "device_id",DeviceId,field_name = "device_name",lowercase(DeviceName),field_name = "process_name",RuleName,field_name = "process_path",RulePath,field_name = "sha1",SHA1,field_name = "sha256",SHA256,field_name = "signer",lowercase(Publisher),field_name = "signature_valid",if(SignatureStatus = "Unavailable","",lowercase(to_string(SignatureValid))),field_name = "remote_host",RemoteHost,field_name = "tool_id",SoftwareId,field_name = "software_role",SoftwareRole,""), _Value = value
| alter _Matches = if(_Actual != null and _Actual != "" and (
    ((operator = "equals" or operator = "exact") and _Actual = _Value)
    or (operator = "path_prefix" and arrayindex(split(_Actual,_Value),0) = "")
    or (operator = "domain_suffix" and (_Actual = _Value or wildcard_match(_Actual,concat("*.",_Value))))
    or (operator = "regex" and ((regex_key = "rx-00b1eea1ce5bf555" and _Actual ~= "^[a-z]:/(?:[^/]+/)*(?:sogouinput|sogouwbinput)/") or (regex_key = "rx-01093cb618136bf9" and _Actual ~= "google (?:llc|inc)") or (regex_key = "rx-044c546878deec89" and _Actual ~= "^[a-z]:/program files(?: \(x86\))?/microsoft office/(?:root/)?office[0-9]+/outlook[.]exe$") or (regex_key = "rx-0b57247b2ac6a0f4" and _Actual ~= "^[a-z]:/(?:program files(?: \(x86\))?|users/[^/]+/appdata/(?:local|roaming))/(?:[^/]+/)*tencent/qqbrowser/(?:[^/]+/)*qqbrowser[.]exe$") or (regex_key = "rx-0be6a609a7bad84e" and _Actual ~= "^(?:beijing sogou technology development co[.]?,? ltd[.]?|tencent technology ?\(shenzhen\) company limited)$") or (regex_key = "rx-0e5ebe390a2f79e3" and _Actual ~= "tencent technology") or (regex_key = "rx-13c0afd36fd00475" and _Actual ~= "^[a-z]:/(?:program files(?: \(x86\))?|users/[^/]+/appdata/(?:local|roaming))/(?:[^/]+/)*mozilla firefox/(?:[^/]+/)*firefox[.]exe$") or (regex_key = "rx-24dab7ec5e8815fe" and _Actual ~= "^[a-z]:/program files(?: \(x86\))?/sogou/sogouexplorer/(?:[^/]+/)*sogouexplorer[.]exe$") or (regex_key = "rx-298ca303877cc97c" and _Actual ~= "mozilla corporation") or (regex_key = "rx-35ec10b0e532e49e" and _Actual ~= "^/Library/(?:ManageEngine/UEMS_Agent|Desktopcentral_Agent)/") or (regex_key = "rx-56adec474d120fa9" and _Actual ~= "^microsoft corporation$") or (regex_key = "rx-64882f7b5785813f" and _Actual ~= "^[a-z]:/program files(?: \(x86\))?/(?:manageengine/uems_agent|desktopcentral_agent)/") or (regex_key = "rx-6867efd356038a2c" and _Actual ~= "^(?:developer id application: )?microsoft corporation(?: \([a-z0-9]+\))?$") or (regex_key = "rx-688de0b47c5f49f2" and _Actual ~= "^[a-z]:/(?:program files(?: \(x86\))?|users/[^/]+/appdata/(?:local|roaming))/(?:[^/]+/)*microsoft/edge/(?:[^/]+/)*msedge[.]exe$") or (regex_key = "rx-72eb8b19dba7c28e" and _Actual ~= "(?:beijing sogou|tencent technology)") or (regex_key = "rx-787bfe07b04bdb03" and _Actual ~= "vivaldi technologies") or (regex_key = "rx-853a065f67a9e16b" and _Actual ~= "^(?:developer id application: )?google (?:llc|inc)(?: \([a-z0-9]+\))?$") or (regex_key = "rx-90da7e269b72988a" and _Actual ~= "(?i)^/(?:applications|users/[^/]+/applications)/google chrome[.]app/contents/(?:macos/google chrome|frameworks/google chrome framework[.]framework/versions/[^/]+/helpers/google chrome helper(?: \((?:renderer|gpu|plugin)\))?[.]app/contents/macos/google chrome helper(?: \((?:renderer|gpu|plugin)\))?)$") or (regex_key = "rx-94a676e01738e3b0" and _Actual ~= "developer id application: zoho corporation") or (regex_key = "rx-97609b3bb0afac4e" and _Actual ~= "^[a-z]:/(?:program files(?: \(x86\))?/tencent/yuanbao|users/[^/]+/(?:appdata/(?:local|roaming)/(?:tencent/)?)?yuanbao)/yuanbao[.]exe$") or (regex_key = "rx-9fc97d738a3f55eb" and _Actual ~= "^[a-z]:/(?:program files(?: \(x86\))?|users/[^/]+/appdata/(?:local|roaming))/(?:[^/]+/)*google/(?:[^/]+/)*chrome[.]exe$") or (regex_key = "rx-b4c6c7c66eb34521" and _Actual ~= "(?i)^/(?:applications|users/[^/]+/applications)/microsoft edge[.]app/contents/(?:macos/microsoft edge|frameworks/microsoft edge framework[.]framework/versions/[^/]+/helpers/microsoft edge helper(?: \((?:renderer|gpu|plugin)\))?[.]app/contents/macos/microsoft edge helper(?: \((?:renderer|gpu|plugin)\))?)$") or (regex_key = "rx-b970c040c317fb0d" and _Actual ~= "^tencent technology ?\(shenzhen\) company limited$") or (regex_key = "rx-bed3ba443c7e66ad" and _Actual ~= "zoho corporation") or (regex_key = "rx-ce4c9ba52e3a31fe" and _Actual ~= "^[a-z]:/(?:program files(?: \(x86\))?/ima[.]copilot|ima[.]copilot|users/[^/]+/appdata/local/ima[.]copilot/application)/ima[.]copilot[.]exe$") or (regex_key = "rx-f43b260c65382b8b" and _Actual ~= "microsoft corporation") or (regex_key = "rx-fc65d1dc59f5b554" and _Actual ~= "^[a-z]:/(?:program files(?: \(x86\))?|users/[^/]+/appdata/(?:local|roaming))/(?:[^/]+/)*vivaldi/(?:[^/]+/)*vivaldi[.]exe$")))),true,false)
| alter _Condition = if(_Matches = true,condition_id,null)
| comp count_distinct(_Condition) as _Matched, max(to_integer(condition_count)) as _Required
    by _time, FirstObserved, _Record, DeviceId, SoftwareId, SoftwareRole, IdentityValid, EvidenceConflict, ProcessMatch, DomainMatch, Evidence, RemoteHost, RemoteIP, _MatchedDomainsJSON, Activity, rule_id, rule_kind, group_id
| alter _GroupHit = if(_Matched = _Required and _Required > 0,1,0)
| comp max(if(rule_kind = "general",_GroupHit,0)) as GeneralHit,
    max(if(rule_kind = "retain",_GroupHit,0)) as RetainHit,
    max(if(rule_kind = "customer" or rule_kind = "general_whitelist",_GroupHit,0)) as WhitelistHit
    by _time, FirstObserved, _Record, DeviceId, SoftwareId, SoftwareRole, IdentityValid, EvidenceConflict, ProcessMatch, DomainMatch, Evidence, RemoteHost, RemoteIP, _MatchedDomainsJSON, Activity
| alter ReportSection = if((IdentityValid = true or ProcessMatch = 1 and DomainMatch = 1) and EvidenceConflict = false and SoftwareRole = "rmm" and (GeneralHit = 0 or RetainHit = 1) and WhitelistHit = 0,"main","review")
| alter _Reason = if(IdentityValid != true and not(ProcessMatch = 1 and DomainMatch = 1),"Additional evidence required",SoftwareRole != "rmm","Outside RMM report scope",WhitelistHit = 1,"Whitelisted",GeneralHit = 1 and RetainHit = 0,"General exclusion","Corroborated RMM activity")
| alter MatchedDomains = json_extract_scalar_array(_MatchedDomainsJSON,"$")
| arrayexpand MatchedDomains
| filter ReportSection = "main"
| windowcomp first_value(_Record) by DeviceId,SoftwareId,ReportSection sort desc _time, asc _Record between null and null as _LatestRecord
| comp min(FirstObserved) as FirstSeen, max(_time) as LastSeen, values(Activity) as Activities,values(_Reason) as Reasons,values(if(RemoteHost = "",null,RemoteHost)) as RemoteHosts,values(if(RemoteIP = "",null,RemoteIP)) as RemoteIPs,values(if(MatchedDomains = "",null,MatchedDomains)) as MatchedDomains,values(Evidence) as Evidence, first(_LatestRecord) as _Record by DeviceId,SoftwareId,ReportSection
| alter DeviceName = json_extract_scalar(_Record,"$[0]"),
    DeviceId = json_extract_scalar(_Record,"$[1]"),
    SoftwareId = json_extract_scalar(_Record,"$[2]"),
    Software = json_extract_scalar(_Record,"$[3]"),
    ProcessName = json_extract_scalar(_Record,"$[4]"),
    ProcessPath = json_extract_scalar(_Record,"$[5]"),
    Publisher = json_extract_scalar(_Record,"$[6]"),
    SHA256 = json_extract_scalar(_Record,"$[7]"),
    User = json_extract_scalar(_Record,"$[8]"),
    RemoteHost = json_extract_scalar(_Record,"$[9]"),
    RemoteIP = json_extract_scalar(_Record,"$[10]"),
    SignatureStatus = json_extract_scalar(_Record,"$[11]")
| alter _HealthKey = 1
 | join type = inner (dataset = rmm_tool_profiles_v2
 | filter release in (dataset = rmm_tool_profiles_v2 | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | comp count() as PRows, count_distinct(row_id) as PKeys,
   count_distinct(release_digest) as PDigests, sum(if(record_type = "manifest",1,0)) as PMarkers,
   max(to_integer(expected_rows)) as PExpected
 | alter POK = if(PRows = add(PExpected,1) and PKeys = PRows
   and PMarkers = 1 and PDigests = 1 and PExpected >= 1,true,false), _HealthKey = 1
 | join type = inner (dataset = rmm_discovery_indicators
 | filter release in (dataset = rmm_discovery_indicators | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | comp count() as DRows, count_distinct(row_id) as DKeys,
   count_distinct(release_digest) as DDigests, sum(if(record_type = "manifest",1,0)) as DMarkers,
   max(to_integer(expected_rows)) as DExpected
 | alter DOK = if(DRows = add(DExpected,1) and DKeys = DRows
   and DMarkers = 1 and DDigests = 1 and DExpected >= 1,true,false), _HealthKey = 1) as DHealth _HealthKey = DHealth._HealthKey
 | join type = inner (dataset = rmm_general_rules
 | filter release in (dataset = rmm_general_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | comp count() as GRows, count_distinct(row_id) as GKeys,
   count_distinct(release_digest) as GDigests, sum(if(record_type = "manifest",1,0)) as GMarkers,
   max(to_integer(expected_rows)) as GExpected
 | alter GOK = if(GRows = add(GExpected,1) and GKeys = GRows
   and GMarkers = 1 and GDigests = 1 and GExpected >= 0,true,false), _HealthKey = 1) as GHealth _HealthKey = GHealth._HealthKey
 | join type = inner (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | comp count() as CRows, count_distinct(row_id) as CKeys,
   count_distinct(release_digest) as CDigests, sum(if(record_type = "manifest",1,0)) as CMarkers,
   max(to_integer(expected_rows)) as CExpected
 | alter COK = if(CRows = add(CExpected,1) and CKeys = CRows
   and CMarkers = 1 and CDigests = 1 and CExpected >= 0,true,false), _HealthKey = 1) as CHealth _HealthKey = CHealth._HealthKey
 | join type = inner (dataset = rmm_general_rules
 | filter release in (dataset = rmm_general_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | union (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release))
 | filter record_type = "condition"
 | filter expires_at = "" or current_time() < parse_timestamp("%Y-%m-%dT%H:%M:%SZ", expires_at)
 | filter rule_kind != "general" or rule_id not in (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release) | filter record_type = "disabled" | fields rule_id)
 | filter operator = "regex" and regex_key not in ("rx-00b1eea1ce5bf555","rx-01093cb618136bf9","rx-044c546878deec89","rx-0b57247b2ac6a0f4","rx-0be6a609a7bad84e","rx-0e5ebe390a2f79e3","rx-13c0afd36fd00475","rx-24dab7ec5e8815fe","rx-298ca303877cc97c","rx-35ec10b0e532e49e","rx-56adec474d120fa9","rx-64882f7b5785813f","rx-6867efd356038a2c","rx-688de0b47c5f49f2","rx-72eb8b19dba7c28e","rx-787bfe07b04bdb03","rx-853a065f67a9e16b","rx-90da7e269b72988a","rx-94a676e01738e3b0","rx-97609b3bb0afac4e","rx-9fc97d738a3f55eb","rx-b4c6c7c66eb34521","rx-b970c040c317fb0d","rx-bed3ba443c7e66ad","rx-ce4c9ba52e3a31fe","rx-f43b260c65382b8b","rx-fc65d1dc59f5b554")
 | comp count() as UnknownRegex
 | alter _HealthKey = 1) as EHealth _HealthKey = EHealth._HealthKey
 | alter ReferencesOK = if(POK = true and DOK = true and GOK = true and COK = true and UnknownRegex = 0,true,false)
 | alter ReportStatus = if(ReferencesOK = true,"ok","reference_or_policy_unavailable")
 | fields _HealthKey, ReferencesOK, ReportStatus) as H _HealthKey = H._HealthKey
 | filter ReferencesOK = true
 | alter ReportStatus = "ok"
| fields DeviceName,Software,LastSeen,FirstSeen,RemoteHosts,RemoteIPs,MatchedDomains,Evidence,ProcessName,ProcessPath,User,Publisher,SignatureStatus,SHA256,Activities,ReportStatus,ReportSection
 | union (dataset = rmm_tool_profiles_v2
 | filter release in (dataset = rmm_tool_profiles_v2 | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | comp count() as PRows, count_distinct(row_id) as PKeys,
   count_distinct(release_digest) as PDigests, sum(if(record_type = "manifest",1,0)) as PMarkers,
   max(to_integer(expected_rows)) as PExpected
 | alter POK = if(PRows = add(PExpected,1) and PKeys = PRows
   and PMarkers = 1 and PDigests = 1 and PExpected >= 1,true,false), _HealthKey = 1
 | join type = inner (dataset = rmm_discovery_indicators
 | filter release in (dataset = rmm_discovery_indicators | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | comp count() as DRows, count_distinct(row_id) as DKeys,
   count_distinct(release_digest) as DDigests, sum(if(record_type = "manifest",1,0)) as DMarkers,
   max(to_integer(expected_rows)) as DExpected
 | alter DOK = if(DRows = add(DExpected,1) and DKeys = DRows
   and DMarkers = 1 and DDigests = 1 and DExpected >= 1,true,false), _HealthKey = 1) as DHealth _HealthKey = DHealth._HealthKey
 | join type = inner (dataset = rmm_general_rules
 | filter release in (dataset = rmm_general_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | comp count() as GRows, count_distinct(row_id) as GKeys,
   count_distinct(release_digest) as GDigests, sum(if(record_type = "manifest",1,0)) as GMarkers,
   max(to_integer(expected_rows)) as GExpected
 | alter GOK = if(GRows = add(GExpected,1) and GKeys = GRows
   and GMarkers = 1 and GDigests = 1 and GExpected >= 0,true,false), _HealthKey = 1) as GHealth _HealthKey = GHealth._HealthKey
 | join type = inner (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | comp count() as CRows, count_distinct(row_id) as CKeys,
   count_distinct(release_digest) as CDigests, sum(if(record_type = "manifest",1,0)) as CMarkers,
   max(to_integer(expected_rows)) as CExpected
 | alter COK = if(CRows = add(CExpected,1) and CKeys = CRows
   and CMarkers = 1 and CDigests = 1 and CExpected >= 0,true,false), _HealthKey = 1) as CHealth _HealthKey = CHealth._HealthKey
 | join type = inner (dataset = rmm_general_rules
 | filter release in (dataset = rmm_general_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release)
 | union (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release))
 | filter record_type = "condition"
 | filter expires_at = "" or current_time() < parse_timestamp("%Y-%m-%dT%H:%M:%SZ", expires_at)
 | filter rule_kind != "general" or rule_id not in (dataset = rmm_customer_rules
 | filter release in (dataset = rmm_customer_rules | filter record_type = "manifest" | sort desc release | limit 1 | fields release) | filter record_type = "disabled" | fields rule_id)
 | filter operator = "regex" and regex_key not in ("rx-00b1eea1ce5bf555","rx-01093cb618136bf9","rx-044c546878deec89","rx-0b57247b2ac6a0f4","rx-0be6a609a7bad84e","rx-0e5ebe390a2f79e3","rx-13c0afd36fd00475","rx-24dab7ec5e8815fe","rx-298ca303877cc97c","rx-35ec10b0e532e49e","rx-56adec474d120fa9","rx-64882f7b5785813f","rx-6867efd356038a2c","rx-688de0b47c5f49f2","rx-72eb8b19dba7c28e","rx-787bfe07b04bdb03","rx-853a065f67a9e16b","rx-90da7e269b72988a","rx-94a676e01738e3b0","rx-97609b3bb0afac4e","rx-9fc97d738a3f55eb","rx-b4c6c7c66eb34521","rx-b970c040c317fb0d","rx-bed3ba443c7e66ad","rx-ce4c9ba52e3a31fe","rx-f43b260c65382b8b","rx-fc65d1dc59f5b554")
 | comp count() as UnknownRegex
 | alter _HealthKey = 1) as EHealth _HealthKey = EHealth._HealthKey
 | alter ReferencesOK = if(POK = true and DOK = true and GOK = true and COK = true and UnknownRegex = 0,true,false)
 | alter ReportStatus = if(ReferencesOK = true,"ok","reference_or_policy_unavailable")
 | fields _HealthKey, ReferencesOK, ReportStatus
 | filter ReportStatus != "ok" | fields ReportStatus)
| alter _Priority = if(ReportStatus != "ok",-1,if(coalesce(ReportSection,"main") = "main",0,1))
 | sort asc _Priority, desc LastSeen
 | fields DeviceName,Software,LastSeen,FirstSeen,RemoteHosts,RemoteIPs,MatchedDomains,Evidence,ProcessName,ProcessPath,User,Publisher,SignatureStatus,SHA256,Activities,ReportStatus
