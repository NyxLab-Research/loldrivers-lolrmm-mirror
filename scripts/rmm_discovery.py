"""Catalog indicators discover candidates; they never grant publisher trust."""
import argparse
import collections
import csv
import hashlib
import json
import re
from pathlib import Path
import rmm_reference_data as ref
import rmm_report_rules as rr

SOURCE=ref.ROOT/'data/rmm_discovery_source.json'
TARGET=ref.ROOT/'data/rmm_discovery_indicators.csv'
FIELDS=ref.DISCOVERY_FIELDS
GENERIC={'agent.exe','client.exe','server.exe','service.exe','setup.exe','updater.exe','update.exe',
         'installer.exe','java.exe','javaw.exe','node.exe','python.exe','svchost.exe','chrome.exe',
         'msedge.exe','firefox.exe','msedgewebview2.exe','powershell.exe','cmd.exe','iexplore.exe'}

def sequence(value):return value if isinstance(value,list) else [value] if value else []

def compact_source(payload):
    tools=json.loads(payload)
    if not isinstance(tools,list) or len(tools)<300:raise ValueError('Incomplete catalog; previous release preserved')
    result=[]
    for tool in tools:
        details=tool.get('Details') or {}
        values=sequence(details.get('InstallationPaths'))
        values += [p.get(k,'') for p in sequence(details.get('PEMetadata')) if isinstance(p,dict) for k in ('Filename','OriginalFileName')]
        patterns=sorted({re.split(r'[\\/]',v)[-1].lower() for v in values if isinstance(v,str) and v})
        result.append({'name':tool['Name'],'patterns':patterns})
    return {'schema_version':1,'source':'https://lolrmm.io/api/rmm_tools.json',
            'source_sha256':hashlib.sha256(payload).hexdigest(),'tools':sorted(result,key=lambda t:t['name'])}

def records(source=None):
    source=source or rr.load_json(SOURCE)
    approved=rr.load_json(ref.ROOT/'rules/rmm_identity_profiles.json')['profiles']
    profiles=[r for r in ref.profiles() if r['record_type']=='profile']
    by_name={r['process_name']:r for r in profiles}
    by_label={name.lower():p for p in approved for name in p['ioc_names']+[p['tool_name']]}
    scope=rr.load_json(ref.ROOT/'rules/rmm_catalog_scope.json')
    scope_overrides={r['catalog_name'].lower():r['software_role'] for r in scope['overrides']}
    if scope.get('schema_version')!=1 or len(scope_overrides)!=len(scope['overrides']) or any(v not in ('management','dual_use') for v in scope_overrides.values()):
        raise ValueError('Invalid reviewed catalog scope override')
    # The reviewed AweSun constraint is canonical; do not split it from its domain labels.
    for p in approved:
        if p['tool_id']=='aweray':p.update(tool_id='awesun',tool_name='AweSun')
    def identity(label):
        p=by_label.get(label.lower())
        return (p['tool_id'],p['tool_name'],p['role']) if p else ('catalog-'+hashlib.sha256(label.encode()).hexdigest()[:16],label,scope_overrides.get(label.lower(),'rmm'))
    proposals=collections.defaultdict(set)
    for tool in source['tools']:
        for pattern in tool['patterns']:
            if pattern.endswith('.exe'):proposals[pattern].add(identity(tool['name']))
    for name,p in by_name.items():proposals[name]={(p['tool_id'],p['tool_name'],p['software_role'])}
    rows=[]
    for pattern,owners in sorted(proposals.items()):
        if pattern in GENERIC or re.search(r'[?<>%{}\[\];]',pattern):continue
        if '*' in pattern:
            # Only a literal family prefix ending at a delimiter, with one bounded wildcard.
            if pattern.count('*')!=1:continue
            prefix,suffix=pattern.split('*')
            if not re.fullmatch(r'[a-z][a-z0-9]{3,}[-_]',prefix) or suffix!='.exe':continue
            anchor='prefix:'+prefix[:-1]
        else:anchor='name:'+pattern
        if len(owners)==1:tid,name,role=next(iter(owners))
        else:
            tid='ambiguous-'+hashlib.sha256(pattern.encode()).hexdigest()[:16]
            name='Ambiguous: '+' / '.join(sorted({r[1] for r in owners}));role='ambiguous'
        rows.append(dict(record_type='process',tool_id=tid,tool_name=name,software_role=role,anchor_key=anchor,pattern=pattern,domain=''))
    with (ref.ROOT/'data/lolrmm_domains.csv').open(encoding='utf-8') as handle:domains=list(csv.DictReader(handle))
    for row in domains:
        tid,name,role=identity(row['rmm_tool'])
        rows.append(dict(record_type='domain',tool_id=tid,tool_name=name,software_role=role,
                         anchor_key='host:'+row['domain'],pattern=row['pattern'].lower(),domain=row['domain']))
    return sorted({rr.digest(r):r for r in rows}.values(),key=rr.digest)

def rows():
    with TARGET.open(encoding='utf-8') as handle:result=list(csv.DictReader(handle))
    ref.validate(result,FIELDS)
    return result

def write(check=False,refresh=False,catalog=None):
    source=rr.load_json(SOURCE) if SOURCE.exists() else None
    if refresh or catalog:
        from sync_sources import fetch,write_bytes
        source=compact_source(Path(catalog).read_bytes() if catalog else fetch('https://lolrmm.io/api/rmm_tools.json'))
    if source is None:raise ValueError('Discovery catalog snapshot required')
    release=rows()[-1]['release'] if TARGET.exists() else '000001'
    data=records(source)
    def sealed(version):return ref.seal([dict(r,row_id=version+':'+rr.digest(r)[:24]) for r in data],FIELDS,version)
    result=sealed(release);payload=ref.csv_bytes(result,FIELDS)
    if check:
        if not TARGET.exists() or TARGET.read_bytes()!=payload:raise ValueError('Discovery reference CSV is stale')
    else:
        if TARGET.exists() and TARGET.read_bytes()!=payload:release=f'{int(release)+1:06d}';result=sealed(release);payload=ref.csv_bytes(result,FIELDS)
        from sync_sources import write_bytes
        write_bytes(SOURCE,(json.dumps(source,ensure_ascii=False,indent=2)+'\n').encode())
        write_bytes(TARGET,payload)
    return {'release':release,'rows':len(result)-1,'domains':sum(r['record_type']=='domain' for r in result),
            'process_patterns':sum(r['record_type']=='process' for r in result)}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',action='store_true');p.add_argument('--refresh',action='store_true');p.add_argument('--catalog',type=Path)
    a=p.parse_args();print(json.dumps(write(a.check,a.refresh,a.catalog)))
