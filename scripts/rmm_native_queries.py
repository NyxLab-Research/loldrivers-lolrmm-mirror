"""Native domain OR process RMM queries; rules are data, not per-rule branches."""
import json
import re
import rmm_reference_data as ref
import rmm_report_rules as rr

BASE='https://raw.githubusercontent.com/NyxLab-Research/loldrivers-lolrmm-mirror/main/data/'
FIELD_EXPRESSIONS={'device_id':'DeviceId','device_name':'tolower(DeviceName)','process_name':'RuleName',
    'process_path':'RulePath','sha1':'SHA1','sha256':'SHA256','signer':'tolower(Publisher)',
    'signature_valid':'iff(SignatureStatus=="Unavailable","",tolower(tostring(SignatureValid)))','remote_host':'RemoteHost','tool_id':'SoftwareId','software_role':'SoftwareRole'}

def replace_stage(text,old,new):
    if text.count(old)!=1:raise ValueError('Native query stage is missing or duplicated')
    return text.replace(old,new,1)

def cortex_suffix(value,suffix):
    tail='concat(".",'+suffix+')'
    return '('+value+' = '+suffix+' or ('+value+' contains '+tail+' and arrayindex(split('+value+','+tail+'),-1) = ""))'

def cortex_glob(value,pattern='pattern'):
    # Discovery permits exact literals or one '*'; avoid tenant-specific wildcard_match.
    parts='split('+pattern+',"*")';prefix='arrayindex('+parts+',0)';suffix='arrayindex('+parts+',1)'
    return '(array_length('+parts+') = 1 and '+value+' = '+pattern+') or (array_length('+parts+') = 2'+\
        ' and len('+value+') >= add(len('+prefix+'),len('+suffix+'))'+\
        ' and ('+prefix+' = "" or ('+value+' contains '+prefix+' and arrayindex(split('+value+','+prefix+'),0) = ""))'+\
        ' and ('+suffix+' = "" or ('+value+' contains '+suffix+' and arrayindex(split('+value+','+suffix+'),-1) = "")))'

def data_source(kind,config,inline=False):
    fields=ref.fields(kind)
    if kind=='customer' or inline:
        import rmm_discovery
        rows=ref.profiles() if kind=='profiles' else rmm_discovery.rows() if kind=='discovery' else ref.policy_rows(config=config,customer=kind=='customer')
        return 'datatable('+','.join(k+':string' for k in fields)+')[\n'+',\n'.join(','.join(rr.quote(r[k]) for k in fields) for r in rows)+'\n]'
    return 'externaldata('+','.join(k+':string' for k in fields)+")[h'"+BASE+ref.REFERENCE_NAMES[kind]+".csv'] with(format='csv',ignoreFirstRecord=true)"

def check_config(policy,config):
    general=rr.load_json(ref.ROOT/'rules/rmm_general_whitelist.json')
    for rule in policy['rules']+general['rules']+config.get('whitelist',[])+config.get('retain_rules',[]):
        if any(c['field'] not in FIELD_EXPRESSIONS for g in rr.groups(rule) for c in g):
            raise ValueError('Native identity policy uses tool_id and remote_host; IOC-label association rules require migration')

def health_mde(name,record_type,min_rows):
    return f'''let {name}Marker=materialize({name}Raw | where record_type=="manifest" | top 1 by release desc);
let {name}Release=toscalar({name}Marker | project release);
let {name}Active=materialize({name}Raw | where release=={name}Release);
let {name}OK=toscalar({name}Active | count)==toscalar({name}Marker | project tolong(expected_rows))+1
 and toscalar({name}Active | summarize by row_id | count)==toscalar({name}Active | count)
 and toscalar({name}Active | summarize by release_digest | count)==1
 and toscalar({name}Marker | project tolong(expected_rows))>={min_rows};
'''

def mde_regex(pool):
    terms=[]
    for key,pattern in pool.items():terms += [rr.quote(key), 'value matches regex '+rr.quote_regex(pattern,'mde')]
    expr='case('+','.join('key=='+terms[i]+','+terms[i+1] for i in range(0,len(terms),2))+',false)' if terms else 'false'
    return 'let MatchRegex=(value:string,key:string){'+expr+'};\n'

def build_mde(policy,config,timeframe='7d',view='main',inline=False):
    check_config(policy,config)
    if not re.fullmatch(r'[1-9][0-9]*[mhd]',timeframe):raise ValueError('Invalid timeframe')
    if view not in ('main','all','review','details'):raise ValueError('Invalid native view')
    pool=ref.regex_pool(policy,config)
    defs='// Native RMM activity; source definitions and integration contract: README.md.\n'
    defs+='let ReportStart=ago('+timeframe+');\nlet ReportEnd=now();\n'
    for kind,name in (('profiles','Profile'),('discovery','Discovery'),('general','General'),('customer','Customer')):
        defs+='let '+name+'Raw=materialize('+data_source(kind,config,inline)+');\n'
        defs+=health_mde(name,'profile' if kind=='profiles' else 'condition',1 if kind in ('profiles','discovery') else 0)
    defs+='let ReferencesOK=ProfileOK and DiscoveryOK and GeneralOK and CustomerOK;\n'
    defs+='let FileProfileEnabled='+str(config.get('mde_file_profile_fallback',True)).lower()+';\n'
    defs+='let Profiles=materialize(ProfileActive | where record_type=="profile");\n'
    defs+='''let Indicators=materialize(DiscoveryActive | where record_type in ("process","domain"));
let ProcessIndicators=materialize(Indicators | where record_type=="process");
let DomainIndicators=materialize(Indicators | where record_type=="domain");
let CandidateNames=toscalar(ProcessIndicators | where anchor_key startswith "name:" | summarize make_set(pattern));
let CandidatePrefixes=toscalar(ProcessIndicators | where anchor_key startswith "prefix:" | summarize make_set(substring(anchor_key,7)));
let MainNamesCovered=toscalar(Profiles | join kind=leftanti (ProcessIndicators | where anchor_key startswith "name:" | project process_name=pattern,tool_id) on process_name,tool_id | count)==0;
let DomainTerms=toscalar(DomainIndicators | extend Term=extract(@"[a-z0-9]{3,}",0,domain) | summarize make_set(Term));
let DomainScan=toscalar(DomainIndicators | where isempty(extract(@"[a-z0-9]{3,}",0,domain)) or not(domain matches regex @"^[a-z0-9.-]+$") | count)>0 or array_length(DomainTerms)>480;
let Terms0=array_slice(DomainTerms,0,119);
let Terms1=array_slice(DomainTerms,120,239);
let Terms2=array_slice(DomainTerms,240,359);
let Terms3=array_slice(DomainTerms,360,479);
'''
    defs+='let Rules=materialize(union GeneralActive,CustomerActive | where record_type=="condition"\n'
    defs+=' | where isempty(expires_at) or now()<todatetime(expires_at)\n'
    defs+=' | where rule_kind!="general" or rule_id !in (CustomerActive | where record_type=="disabled" | project rule_id));\n'
    defs+='let RegexKeys=dynamic('+json.dumps(list(pool))+');\n'
    defs+='let EngineOK=toscalar(Rules | where operator=="regex" and regex_key !in (RegexKeys) | count)==0;\n'
    defs+=mde_regex(pool)
    defs+='''let NormalizePath=(value:string){iff(value matches regex @"^[A-Za-z]:",tolower(replace_string(value,"\\\\","/")),value)};
let OriginalAlias=(value:string){let name=tolower(value);iff(name endswith ".exe" or name in (CandidateNames),name,strcat(name,".exe"))};
let FullPath=(folder:string,name:string){iff(tolower(folder) endswith tolower(name),folder,strcat(trim_end(@"[\\\\/]+",folder),iff(folder contains "\\\\","\\\\","/"),name))};
let Host=(value:string){tolower(trim_end(@"[.]+",tostring(parse_url(iff(value contains "://",value,strcat("https://",value))).Host)))};
let NameCandidate=(name:string){name in (CandidateNames) or tostring(split(name,"-")[0]) in (CandidatePrefixes) or tostring(split(name,"_")[0]) in (CandidatePrefixes)};
let Sources=(union
 (DeviceNetworkEvents
  | where Timestamp>=ReportStart and Timestamp<ReportEnd
  | where ActionType=="ConnectionSuccess" or NameCandidate(tolower(InitiatingProcessFileName)) or NameCandidate(OriginalAlias(InitiatingProcessVersionInfoOriginalFileName))
  | where DomainScan or RemoteUrl has_any (Terms0) or RemoteUrl has_any (Terms1) or RemoteUrl has_any (Terms2) or RemoteUrl has_any (Terms3)
     or RemoteIP has_any (Terms0) or RemoteIP has_any (Terms1) or RemoteIP has_any (Terms2) or RemoteIP has_any (Terms3)
     or NameCandidate(tolower(InitiatingProcessFileName)) or NameCandidate(OriginalAlias(InitiatingProcessVersionInfoOriginalFileName))
  | where isnotempty(RemoteUrl) or isnotempty(RemoteIP) or NameCandidate(tolower(InitiatingProcessFileName)) or NameCandidate(OriginalAlias(InitiatingProcessVersionInfoOriginalFileName))
  | project _time=Timestamp,DeviceName,DeviceId,ProcessName=InitiatingProcessFileName,
    ProcessPath=InitiatingProcessFolderPath,SHA1=tolower(InitiatingProcessSHA1),SHA256=tolower(InitiatingProcessSHA256),
    OriginalName=InitiatingProcessVersionInfoOriginalFileName,User=InitiatingProcessAccountName,
    RemoteHost=iff(isnotempty(RemoteUrl),Host(RemoteUrl),RemoteIP),RemoteIP,Activity=iff(ActionType=="ConnectionSuccess","Network activity","Connection attempt"),ActionType),
 (DeviceProcessEvents
  | where Timestamp>=ReportStart and Timestamp<ReportEnd and ActionType=="ProcessCreated"
  | where NameCandidate(tolower(FileName)) or NameCandidate(OriginalAlias(ProcessVersionInfoOriginalFileName))
  | project _time=Timestamp,DeviceName,DeviceId,ProcessName=FileName,ProcessPath=FullPath(FolderPath,FileName),
    SHA1=tolower(SHA1),SHA256=tolower(SHA256),OriginalName=ProcessVersionInfoOriginalFileName,
    User=AccountName,RemoteHost="",RemoteIP="",Activity="Process start",ActionType)
 | extend RuleName=tolower(ProcessName),RuleOriginal=tolower(OriginalName),OriginalKey=OriginalAlias(OriginalName),RulePath=NormalizePath(ProcessPath)
 | extend SourceId=tostring(pack_array(DeviceId,ProcessName,ProcessPath,SHA1,SHA256,OriginalName,User,RemoteHost,RemoteIP,Activity,ActionType)));
let ProcessCandidates=Sources
 | extend MatchKeys=pack_array(strcat("name:",RuleName),strcat("name:",OriginalKey),strcat("prefix:",tostring(split(RuleName,"-")[0])),strcat("prefix:",tostring(split(RuleName,"_")[0])))
 | mv-expand MatchKey=MatchKeys to typeof(string)
 | lookup kind=inner ProcessIndicators on $left.MatchKey==$right.anchor_key
 | extend Parts=split(pattern,"*")
 | where (array_length(Parts)==1 and (RuleName==pattern or OriginalKey==pattern))
    or (array_length(Parts)==2 and RuleName startswith_cs tostring(Parts[0]) and RuleName endswith_cs tostring(Parts[1]) and strlen(RuleName)>=strlen(tostring(Parts[0]))+strlen(tostring(Parts[1])))
 | summarize FirstObserved=min(_time),_time=max(_time),EventCount=count() by SourceId,DeviceName,DeviceId,ProcessName,ProcessPath,SHA1,SHA256,OriginalName,User,RemoteHost,RemoteIP,Activity,ActionType,RuleName,RuleOriginal,OriginalKey,RulePath,tool_id,tool_name,software_role
 | extend ProcessMatch=1,DomainMatch=0,MatchedDomain="";
let DomainCandidates=Sources | where Activity=="Network activity" and isnotempty(RemoteHost)
 | extend Labels=split(RemoteHost,".")
 | mv-expand LabelIndex=range(0,array_length(Labels)-1,1) to typeof(long)
 | extend DomainKey=strcat("host:",strcat_array(array_slice(Labels,LabelIndex,-1),"."))
 | lookup kind=inner DomainIndicators on $left.DomainKey==$right.anchor_key
 | extend Parts=split(pattern,"*")
 | where (array_length(Parts)==1 and RemoteHost==pattern)
    or (array_length(Parts)==2 and RemoteHost startswith_cs tostring(Parts[0]) and RemoteHost endswith_cs tostring(Parts[1]) and strlen(RemoteHost)>=strlen(tostring(Parts[0]))+strlen(tostring(Parts[1])))
 | summarize FirstObserved=min(_time),_time=max(_time),EventCount=count() by SourceId,DeviceName,DeviceId,ProcessName,ProcessPath,SHA1,SHA256,OriginalName,User,RemoteHost,RemoteIP,Activity,ActionType,RuleName,RuleOriginal,OriginalKey,RulePath,tool_id,tool_name,software_role,domain
 | extend ProcessMatch=0,DomainMatch=1,MatchedDomain=domain;
let Raw=materialize(union (ProcessCandidates),(DomainCandidates)
 | summarize ProcessMatch=max(ProcessMatch),DomainMatch=max(DomainMatch),MatchedDomains=make_set_if(MatchedDomain,isnotempty(MatchedDomain)),arg_max(_time,*) by SourceId,tool_id
 | project-away domain
 | extend SoftwareId=tool_id,Software=tool_name,SoftwareRole=software_role
 | project-away tool_id,tool_name,software_role
 | lookup kind=leftouter Profiles on $left.RuleName==$right.process_name
 | lookup kind=leftouter (Profiles | project OriginalAlias=process_name,OriginalTool=tool_id,
     OriginalSoftware=tool_name,OriginalRole=software_role,OriginalSigners=signers,
     OriginalPrefix=path_prefix,OriginalContains=path_contains,OriginalNames=original_names) on $left.OriginalKey==$right.OriginalAlias
 | extend ProfileTool=coalesce(tool_id,OriginalTool),ExpectedSigners=coalesce(signers,OriginalSigners),
     RequiredPrefix=coalesce(path_prefix,OriginalPrefix),RequiredContains=coalesce(path_contains,OriginalContains),
     AllowedOriginalNames=coalesce(original_names,OriginalNames),
     NameConflict=isnotempty(tool_id) and isnotempty(OriginalTool) and tool_id!=OriginalTool
 | project _time,FirstObserved,EventCount,DeviceName,DeviceId,SoftwareId,Software,SoftwareRole,ProcessName,ProcessPath,SHA1,SHA256,ProfileTool,ProcessMatch,DomainMatch,MatchedDomains,RemoteIP,
     OriginalName,RuleName,RuleOriginal,RulePath,ExpectedSigners,RequiredPrefix,RequiredContains,AllowedOriginalNames,
     NameConflict,User,RemoteHost,Activity,ActionType);
let LocalCertificates=DeviceFileCertificateInfo
 | where Timestamp>=ReportStart and Timestamp<ReportEnd
 | extend SHA1=tolower(SHA1)
 | where SHA1 in (Raw | where isnotempty(SHA1) | distinct SHA1)
 | project Timestamp,DeviceId,SHA1,IsSigned,IsTrusted,Signer
 | summarize arg_max(Timestamp,*) by DeviceId,SHA1
 | project DeviceId,SHA1=tolower(SHA1),LocalSeen=true,LocalSigned=IsSigned,LocalTrusted=IsTrusted,LocalSigner=Signer;
let WithLocal=materialize(Raw | lookup kind=leftouter LocalCertificates on DeviceId,SHA1);
let MissingHashes=materialize(WithLocal
 | where FileProfileEnabled and coalesce(LocalSeen,false)==false and SHA1 matches regex @"^[a-f0-9]{40}$"
 | where ProfileTool==SoftwareId or RuleName in (Rules | where anchor_key startswith "name:" | project substring(anchor_key,5))
 | distinct SHA1);
let CloudOverflow=toscalar(MissingHashes | count)>1000;
let Cloud=materialize(MissingHashes | sort by SHA1 asc | take 1000 | invoke FileProfile("SHA1",1000)
 | project SHA1,CloudSHA256=tolower(SHA256),CloudSigner=Signer,
   CloudValid=ProfileAvailability=="Available" and SignatureState=="SignedValid" and tostring(IsCertificateValid) in~ ("true","1"),
   CloudError=ProfileAvailability=="Error");
let CloudFailed=toscalar(Cloud | where CloudError | count)>0;
let Candidates=materialize(WithLocal | lookup kind=leftouter Cloud on SHA1
 | extend Publisher=iff(LocalSeen==true,LocalSigner,CloudSigner),
     SignatureValid=iff(coalesce(LocalSeen,false),coalesce(LocalSigned,false) and coalesce(LocalTrusted,false),coalesce(CloudValid,false)),
     SignatureSource=iff(LocalSeen==true,"device_sha1",iff(isnotempty(CloudSigner),"file_profile","missing")),
     HashConflict=isnotempty(SHA256) and isnotempty(CloudSHA256) and SHA256!=CloudSHA256
 | extend PathOK=(isempty(RequiredPrefix) or RulePath startswith_cs RequiredPrefix)
     and (isempty(RequiredContains) or RulePath contains_cs RequiredContains),
     OriginalConflict=isnotempty(RuleOriginal) and not(AllowedOriginalNames contains_cs strcat(";",RuleOriginal,";"))
 | extend IdentityValid=ProfileTool==SoftwareId and SignatureValid and isnotempty(Publisher) and ExpectedSigners contains_cs strcat(";",tolower(Publisher),";")
     and PathOK and not(NameConflict or HashConflict or OriginalConflict),
     CandidateId=tostring(pack_array(DeviceId,SoftwareId,ProcessName,ProcessPath,SHA1,SHA256,Publisher,User,RemoteHost,Activity,_time))
 | extend EvidenceConflict=coalesce(NameConflict,false) or coalesce(HashConflict,false) or (ProfileTool==SoftwareId and (coalesce(OriginalConflict,false) or not(coalesce(PathOK,true))))
 | extend Evidence=case(EvidenceConflict,"Conflicting file metadata",SoftwareRole=="ambiguous","Ambiguous process name",IdentityValid,"Verified process identity",ProcessMatch==1 and DomainMatch==1,"Process and domain match",DomainMatch==1,"Domain match only","Process match only"),
     SignatureStatus=case(SignatureValid,"Valid",SignatureSource=="missing","Unavailable","Not valid or not trusted")
 | project _time,FirstObserved,EventCount,DeviceName,DeviceId,SoftwareId,Software,SoftwareRole,ProcessName,ProcessPath,SHA1,SHA256,ProcessMatch,DomainMatch,MatchedDomains,RemoteIP,Evidence,SignatureStatus,EvidenceConflict,
     RuleName,RulePath,User,RemoteHost,Activity,ActionType,Publisher,SignatureValid,SignatureSource,IdentityValid,CandidateId);
let RuleMatches=Candidates
 | project CandidateId,DeviceId,DeviceName,RuleName,RulePath,SHA1,SHA256,Publisher,SignatureStatus,SignatureValid,RemoteHost,SoftwareId,SoftwareRole
 | extend PolicyKeys=pack_array(strcat("name:",RuleName),strcat("tool:",SoftwareId),"*")
 | mv-expand PolicyKey=PolicyKeys to typeof(string)
 | lookup kind=inner Rules on $left.PolicyKey==$right.anchor_key
'''
    fieldcase=','.join('field_name=='+rr.quote(k)+','+v for k,v in FIELD_EXPRESSIONS.items())
    defs+=' | extend Actual=case('+fieldcase+',""),RuleValue=value\n'
    defs+=''' | where isnotempty(Actual)
 | where (operator in ("equals","exact") and Actual==RuleValue)
   or (operator=="path_prefix" and Actual startswith_cs RuleValue)
   or (operator=="domain_suffix" and (Actual==RuleValue or Actual endswith_cs strcat(".",RuleValue)))
   or (operator=="regex" and MatchRegex(Actual,regex_key))
 | summarize MatchedConditions=dcount(condition_id),RequiredConditions=max(tolong(condition_count))
   by CandidateId,rule_id,rule_kind,group_id
 | where MatchedConditions==RequiredConditions
 | summarize GeneralHits=make_set_if(rule_id,rule_kind=="general"),RetainHits=make_set_if(rule_id,rule_kind=="retain"),
   WhitelistHits=make_set_if(rule_id,rule_kind in ("customer","general_whitelist")) by CandidateId;
let Classified=Candidates | lookup kind=leftouter RuleMatches on CandidateId
 | extend GeneralHits=coalesce(GeneralHits,dynamic([])),RetainHits=coalesce(RetainHits,dynamic([])),WhitelistHits=coalesce(WhitelistHits,dynamic([]))
 | extend GeneralExcluded=array_length(GeneralHits)>0 and not(array_length(RetainHits)>0),
     Whitelisted=array_length(WhitelistHits)>0
 | extend ReportSection=iff((IdentityValid or (ProcessMatch==1 and DomainMatch==1)) and SoftwareRole=="rmm" and not(EvidenceConflict or GeneralExcluded or Whitelisted),"main","review");
'''
    if view in ('main','details'):
        # Unknown domain-only records cannot enter main. Fall back to full discovery if a profile alias is missing.
        defs=replace_stage(defs,'| where Timestamp>=ReportStart and Timestamp<ReportEnd\n  | where ActionType=="ConnectionSuccess"',
            '| where Timestamp>=ReportStart and Timestamp<ReportEnd\n  | where not(MainNamesCovered) or NameCandidate(tolower(InitiatingProcessFileName)) or NameCandidate(OriginalAlias(InitiatingProcessVersionInfoOriginalFileName))\n  | where ActionType=="ConnectionSuccess"')
        # Only records that cannot qualify are removed; domain/process discovery is unchanged.
        defs=replace_stage(defs,'NameConflict,User,RemoteHost,Activity,ActionType);',
            'NameConflict,User,RemoteHost,Activity,ActionType\n | where SoftwareRole=="rmm" and (ProfileTool==SoftwareId or (ProcessMatch==1 and DomainMatch==1)));')
        defs=replace_stage(defs,'SignatureValid,SignatureSource,IdentityValid,CandidateId);',
            'SignatureValid,SignatureSource,IdentityValid,CandidateId\n | where (IdentityValid or (ProcessMatch==1 and DomainMatch==1)) and not(EvidenceConflict));')
    selection='ReportSection=="main"' if view in ('main','details') else 'ReportSection=="review" and not(Whitelisted)' if view=='review' else 'true'
    defs+='Classified | where ReferencesOK and EngineOK and '+selection+'\n'
    if view=='details':
        defs+=' | summarize FirstSeen=min(FirstObserved),LastSeen=max(_time),Activities=make_set(Activity),RemoteHosts=make_set_if(RemoteHost,isnotempty(RemoteHost)),RemoteIPs=make_set_if(RemoteIP,isnotempty(RemoteIP)),MatchedDomains=make_set(MatchedDomains),Evidence=make_set(Evidence),arg_max(_time,*) by DeviceId,SoftwareId,ProcessName,ProcessPath,SHA256,SHA1,ReportSection\n'
    else:
        defs+=' | summarize FirstSeen=min(FirstObserved),LastSeen=max(_time),Activities=make_set(Activity),RemoteHosts=make_set_if(RemoteHost,isnotempty(RemoteHost)),RemoteIPs=make_set_if(RemoteIP,isnotempty(RemoteIP)),MatchedDomains=make_set(MatchedDomains),Evidence=make_set(Evidence),arg_max(_time,*) by DeviceId,SoftwareId,ReportSection\n'
    defs+=' | extend ReportStatus=iff(CloudOverflow or CloudFailed,"enrichment_incomplete","ok")\n'
    fields='DeviceName,Software,LastSeen,FirstSeen,RemoteHosts,RemoteIPs,MatchedDomains,Evidence,ProcessName,ProcessPath,User,Publisher,SignatureStatus,SHA256,Activities,ReportStatus'
    if view=='details':fields+=',SHA1'
    if view not in ('main','details'):fields+=',ReportSection,GeneralHits,RetainHits,WhitelistHits,SignatureSource,IdentityValid'
    defs+=' | project '+fields+'\n'
    defs+=' | union (print ReportStatus=case(not(ReferencesOK),"reference_data_unavailable",not(EngineOK),"policy_engine_mismatch",CloudOverflow or CloudFailed,"enrichment_incomplete","ok") | where ReportStatus!="ok")\n'
    defs+=' | extend _Priority=iff(ReportStatus!="ok",-1,iff(column_ifexists("ReportSection","main")=="main",0,1))\n | order by _Priority asc,LastSeen desc | project-away _Priority\n'
    return defs

def cortex_active(kind):
    name=ref.REFERENCE_NAMES[kind]
    return f'dataset = {name}\n | filter release in (dataset = {name} | filter record_type = "manifest" | sort desc release | limit 1 | fields release)'

def cortex_rules():
    return '('+cortex_active('general')+'\n | union ('+cortex_active('customer')+''')
 | filter record_type = "condition"
 | filter expires_at = "" or current_time() < parse_timestamp("%Y-%m-%dT%H:%M:%SZ", expires_at)
 | filter rule_kind != "general" or rule_id not in ('''+cortex_active('customer')+''' | filter record_type = "disabled" | fields rule_id))'''

def cortex_health(pool):
    result=''
    for kind,prefix,minimum in (('profiles','P',1),('discovery','D',1),('general','G',0),('customer','C',0)):
        part=cortex_active(kind)+f'''
 | comp count() as {prefix}Rows, count_distinct(row_id) as {prefix}Keys,
   count_distinct(release_digest) as {prefix}Digests, sum(if(record_type = "manifest",1,0)) as {prefix}Markers,
   max(to_integer(expected_rows)) as {prefix}Expected
 | alter CheckOK = if({prefix}Rows = add({prefix}Expected,1) and {prefix}Keys = {prefix}Rows
   and {prefix}Markers = 1 and {prefix}Digests = 1 and {prefix}Expected >= {minimum},true,false), CheckName = "{kind}"
 | fields CheckName,CheckOK'''
        result=part if not result else result+'\n | union ('+part+')'
    keys='('+','.join(rr.quote(k,'cortex') for k in pool)+')'
    engine=cortex_rules()[1:-1]+f'\n | filter operator = "regex" and regex_key not in {keys}\n | comp count() as UnknownRegex\n | alter CheckName = "engine",CheckOK = if(UnknownRegex = 0,true,false)\n | fields CheckName,CheckOK'
    result+='\n | union ('+engine+')'
    result+='\n | comp count() as Checks,count_distinct(CheckName) as CheckNames,sum(if(CheckOK = true,1,0)) as Passed'
    result+='\n | alter ReferencesOK = if(Checks = 5 and CheckNames = 5 and Passed = 5,true,false), _HealthKey = 1'
    result+='\n | alter ReportStatus = if(ReferencesOK = true,"ok","reference_or_policy_unavailable")\n | fields _HealthKey, ReferencesOK, ReportStatus'
    return result

def build_cortex(policy,config,timeframe='7d',view='main'):
    check_config(policy,config)
    if any(not rr.supports(r,'cortex') for r in config.get('whitelist',[])+config.get('retain_rules',[])):
        raise ValueError('Cortex policy supports SHA256; SHA1 conditions require an MDE-only query')
    if not re.fullmatch(r'[1-9][0-9]*[mhd]',timeframe):raise ValueError('Invalid timeframe')
    if view not in ('main','all','review','details'):raise ValueError('Invalid native view')
    pool=ref.regex_pool(policy,config);health=cortex_health(pool)
    profiles=cortex_active('profiles')+'\n | filter record_type = "profile"'
    discovery=cortex_active('discovery')
    process=discovery+'\n | filter record_type = "process"'
    domains=discovery+'\n | filter record_type = "domain"'
    # A broad prefilter may include retained old aliases; the subsequent join validates the active release.
    prefilter='dataset = '+ref.REFERENCE_NAMES['discovery']+' | filter record_type = "process"'
    def domain_key(host):
        # A bucket, not an identity: full domain boundaries and patterns are checked after joining.
        labels='split('+host+',".")'
        return 'if(array_length('+labels+') > 1,concat("suffix:",arrayindex('+labels+',-2),".",arrayindex('+labels+',-1)),concat("single:",'+host+'))'
    domain_index=domains+'\n | alter _DomainKey = '+domain_key('domain')+'\n | fields tool_id,tool_name,software_role,domain,pattern,_DomainKey'
    domain_anchor='''| alter _DomainKey = arraycreate('''+domain_key('RemoteHost')+''',concat("single:",arrayindex(split(RemoteHost,"."),-1)))
| arrayexpand _DomainKey
| filter _DomainKey in ('''+domain_index+''' | fields _DomainKey)
'''
    def source(predicate):
        return 'dataset = xdr_data\n | filter '+predicate+r'''
| fields _time,event_type,agent_hostname,agent_id,actor_process_image_name,actor_process_image_path,actor_process_image_sha256,
    actor_process_signature_vendor,actor_process_signature_status,actor_primary_username,action_external_hostname,action_remote_ip,
    action_process_image_name,action_process_image_path,action_process_image_sha256,action_process_signature_vendor,action_process_signature_status
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
| comp min(_time) as FirstObserved,max(_time) as _time,count() as EventCount by DeviceName,DeviceId,ProcessName,ProcessPath,SHA256,Publisher,SignatureValid,SignatureStatus,User,RemoteHost,RemoteIP,Activity,SHA1,RuleName,RulePath
'''
    network='event_type = ENUM.NETWORK and ((action_external_hostname != null and action_external_hostname != "") or action_remote_ip != null)'
    process_predicate='event_type = ENUM.NETWORK or (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START)'
    network_source=replace_stage(source(network),'| comp min(_time)',domain_anchor+'| comp min(_time)')
    network_source=replace_stage(network_source,'Activity,SHA1,RuleName,RulePath\n','Activity,SHA1,RuleName,RulePath,_DomainKey\n')
    query='// Native RMM activity; source definitions and integration contract: README.md.\nconfig case_sensitive = true timeframe = '+timeframe+'\n| '+network_source
    query+='| join type = inner ('+domain_index+') as D _DomainKey = D._DomainKey\n'
    query+='| filter '+cortex_suffix('RemoteHost','domain')+' and ('+cortex_glob('RemoteHost')+')\n| alter ProcessMatch = 0, DomainMatch = 1, MatchedDomain = domain\n'
    anchor_stage='''| alter _IndicatorAnchor = arraycreate(concat("name:",RuleName),concat("prefix:",arrayindex(split(RuleName,"-"),0)),concat("prefix:",arrayindex(split(RuleName,"_"),0)))
| arrayexpand _IndicatorAnchor
| filter _IndicatorAnchor in ('''+prefilter+''' | fields anchor_key)
'''
    process_source=replace_stage(source(process_predicate),'| comp min(_time)',anchor_stage+'| comp min(_time)')
    process_source=replace_stage(process_source,'Activity,SHA1,RuleName,RulePath\n','Activity,SHA1,RuleName,RulePath,_IndicatorAnchor\n')
    query+='| union ('+process_source+' | join type = inner ('+process+' | fields tool_id,tool_name,software_role,pattern,anchor_key) as I _IndicatorAnchor = I.anchor_key\n | filter '+cortex_glob('RuleName')+'\n | alter ProcessMatch = 1, DomainMatch = 0, MatchedDomain = "")\n'
    query+='''| comp max(ProcessMatch) as ProcessMatch,max(DomainMatch) as DomainMatch,values(MatchedDomain) as MatchedDomains,max(EventCount) as EventCount
    by _time,FirstObserved,DeviceName,DeviceId,ProcessName,ProcessPath,SHA256,Publisher,SignatureValid,SignatureStatus,User,RemoteHost,RemoteIP,Activity,SHA1,RuleName,RulePath,tool_id,tool_name,software_role
| alter SoftwareId = tool_id, Software = tool_name, SoftwareRole = software_role
| fields _time,FirstObserved,EventCount,DeviceName,DeviceId,ProcessName,ProcessPath,SHA256,Publisher,SignatureValid,SignatureStatus,User,RemoteHost,RemoteIP,Activity,SHA1,RuleName,RulePath,SoftwareId,Software,SoftwareRole,ProcessMatch,DomainMatch,MatchedDomains
| join type = left ('''+profiles+''' | fields process_name,tool_id,signers,path_prefix,path_contains) as P RuleName = P.process_name
| alter IdentityValid = if(tool_id = SoftwareId and SignatureValid = true and Publisher != "" and signers contains concat(";",lowercase(Publisher),";")
    and (path_prefix = "" or RulePath contains path_prefix and arrayindex(split(RulePath,path_prefix),0) = "")
    and (path_contains = "" or RulePath contains path_contains),true,false),
    EvidenceConflict = if(tool_id = SoftwareId and ((path_prefix != "" and not(RulePath contains path_prefix and arrayindex(split(RulePath,path_prefix),0) = "")) or (path_contains != "" and not(RulePath contains path_contains))),true,false)
| alter Evidence = if(EvidenceConflict = true,"Conflicting file metadata",SoftwareRole = "ambiguous","Ambiguous process name",IdentityValid = true,"Verified process identity",ProcessMatch = 1 and DomainMatch = 1,"Process and domain match",DomainMatch = 1,"Domain match only","Process match only"),
    _MatchedDomainsJSON = to_json_string(MatchedDomains),
    _Record = to_json_string(arraycreate(DeviceName,DeviceId,SoftwareId,Software,ProcessName,ProcessPath,Publisher,SHA256,User,RemoteHost,RemoteIP,SignatureStatus)),
    _PolicyKey = arraycreate(concat("name:",RuleName),concat("tool:",SoftwareId),"*")
| arrayexpand _PolicyKey
| join type = left ('''+cortex_rules()[1:-1]+''') as R _PolicyKey = R.anchor_key
'''
    fields={k:v for k,v in FIELD_EXPRESSIONS.items()}
    fields.update(device_name='lowercase(DeviceName)',signer='lowercase(Publisher)',signature_valid='if(SignatureStatus = "Unavailable","",lowercase(to_string(SignatureValid)))')
    pairs=[rr.quote(k,'cortex')+','+v for k,v in fields.items()]
    # XQL if is variadic. KQL regex patterns stay constants in the generated engine.
    query+='| alter _Actual = if('+','.join('field_name = '+p for p in pairs)+',""), _Value = value\n'
    regexp=' or '.join('(regex_key = '+rr.quote(k,'cortex')+' and _Actual ~= '+rr.quote_regex(p,'cortex')+')' for k,p in pool.items()) or 'false'
    query+='''| alter _Matches = if(_Actual != null and _Actual != "" and (
    ((operator = "equals" or operator = "exact") and _Actual = _Value)
    or (operator = "path_prefix" and arrayindex(split(_Actual,_Value),0) = "")
    or (operator = "domain_suffix" and '''+cortex_suffix('_Actual','_Value')+''')
    or (operator = "regex" and ('''+regexp+'''))),true,false)
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
'''
    if view in ('main','details'):query+='| filter ReportSection = "main"\n'
    elif view=='review':query+='| filter ReportSection = "review" and WhitelistHit = 0\n'
    if view=='details':
        query+='| alter MatchedDomains = json_extract_array(_MatchedDomainsJSON,"$")\n| arrayexpand MatchedDomains\n| alter MatchedDomains = json_extract_scalar(to_string(MatchedDomains),"$")\n'
        query+='| comp min(FirstObserved) as FirstSeen, max(_time) as LastSeen, values(Activity) as Activities,values(_Reason) as Reasons,values(if(RemoteHost = "",null,RemoteHost)) as RemoteHosts,values(if(RemoteIP = "",null,RemoteIP)) as RemoteIPs,values(if(MatchedDomains = "",null,MatchedDomains)) as MatchedDomains,values(Evidence) as Evidence by _Record,ReportSection\n'
    else:
        query+='| windowcomp first_value(_Record) by DeviceId,SoftwareId,ReportSection sort desc _time, asc _Record between null and null as _LatestRecord\n'
        query+='| alter MatchedDomains = json_extract_array(_MatchedDomainsJSON,"$")\n| arrayexpand MatchedDomains\n| alter MatchedDomains = json_extract_scalar(to_string(MatchedDomains),"$")\n'
        query+='| comp min(FirstObserved) as FirstSeen, max(_time) as LastSeen, values(Activity) as Activities,values(_Reason) as Reasons,values(if(RemoteHost = "",null,RemoteHost)) as RemoteHosts,values(if(RemoteIP = "",null,RemoteIP)) as RemoteIPs,values(if(MatchedDomains = "",null,MatchedDomains)) as MatchedDomains,values(Evidence) as Evidence, first(_LatestRecord) as _Record by DeviceId,SoftwareId,ReportSection\n'
    names=['DeviceName','DeviceId','SoftwareId','Software','ProcessName','ProcessPath','Publisher','SHA256','User','RemoteHost','RemoteIP','SignatureStatus']
    query+='| alter '+',\n    '.join(n+' = json_extract_scalar(_Record,"$['+str(i)+']")' for i,n in enumerate(names))+'\n'
    query+='| alter _HealthKey = 1\n | join type = inner ('+health+') as H _HealthKey = H._HealthKey\n | filter ReferencesOK = true\n | alter ReportStatus = "ok"\n'
    fields='DeviceName,Software,LastSeen,FirstSeen,RemoteHosts,RemoteIPs,MatchedDomains,Evidence,ProcessName,ProcessPath,User,Publisher,SignatureStatus,SHA256,Activities,ReportStatus'
    if view not in ('main','details'):fields+=',ReportSection,Reasons'
    query+='| fields '+fields+(',ReportSection' if view in ('main','details') else '')+'\n | union ('+health+'\n | filter ReportStatus != "ok" | fields ReportStatus)\n'
    query+='| alter _Priority = if(ReportStatus != "ok",-1,if(coalesce(ReportSection,"main") = "main",0,1))\n | sort asc _Priority, desc LastSeen\n | fields '+fields+'\n'
    if view in ('main','details'):
        # Evidence is known before policy expansion; retain/whitelist cannot promote it.
        query=replace_stage(query,'| alter Evidence =',
            '| filter SoftwareRole = "rmm" and EvidenceConflict = false and (IdentityValid = true or ProcessMatch = 1 and DomainMatch = 1)\n| alter Evidence =')
        query=re.sub(r'\| alter _Reason = [^\n]+\n','',query)
        query=query.replace('values(_Reason) as Reasons,','')
    return query
