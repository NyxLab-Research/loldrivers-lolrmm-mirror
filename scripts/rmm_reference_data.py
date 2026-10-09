"""Versioned identity/policy tables for native queries; no credentials or APIs."""
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import rmm_report_rules as rr

ROOT = Path(__file__).resolve().parents[1]
RELEASE = '000001'
PROFILE_FIELDS = ('row_id','record_type','release','tool_id','tool_name','process_name','signers',
                  'software_role','path_prefix','path_contains','original_names','expected_rows','release_digest')
POLICY_FIELDS = ('row_id','record_type','release','rule_id','rule_kind','rule_target','group_id',
                 'condition_id','condition_count','anchor_key','field_name','operator','value','regex_key',
                 'expires_at','expected_rows','release_digest')
REFERENCE_NAMES = {'profiles':'rmm_tool_profiles_v2','general':'rmm_general_rules','customer':'rmm_customer_rules'}

def seal(records, fields, release=RELEASE):
    if not re.fullmatch(r'[0-9]{6}', release): raise ValueError('Invalid reference release')
    normalized = [{k:str(r.get(k, '')) for k in fields} for r in records]
    for row in normalized: row.update(release=release, expected_rows='', release_digest='')
    if len({r['row_id'] for r in normalized}) != len(normalized): raise ValueError('Duplicate reference row ID')
    normalized.sort(key=lambda r:r['row_id'])
    digest=rr.digest(normalized)
    for row in normalized: row.update(expected_rows=str(len(normalized)),release_digest=digest)
    marker=dict.fromkeys(fields,'')
    marker.update(row_id=release+':manifest',record_type='manifest',release=release,
                  expected_rows=str(len(normalized)),release_digest=digest)
    return normalized+[marker]

def validate(records, fields):
    markers=[r for r in records if r['record_type']=='manifest']
    if len(markers)!=1: raise ValueError('Exactly one reference manifest required')
    marker=markers[0]
    rows=[{k:str(r.get(k,'')) for k in fields} for r in records if r['record_type']!='manifest']
    if len(rows)!=int(marker['expected_rows']) or len({r['row_id'] for r in rows})!=len(rows):
        raise ValueError('Incomplete or duplicate reference release')
    if any(r['release']!=marker['release'] or r['release_digest']!=marker['release_digest'] for r in rows):
        raise ValueError('Mixed reference release')
    if rr.digest([dict(r,expected_rows='',release_digest='') for r in sorted(rows,key=lambda r:r['row_id'])])!=marker['release_digest']:
        raise ValueError('Reference content digest mismatch')
    return marker

def csv_bytes(records, fields):
    buf=io.StringIO(newline='');writer=csv.DictWriter(buf,fieldnames=fields,lineterminator='\n')
    writer.writeheader();writer.writerows(records);return buf.getvalue().encode('utf-8')

def profiles():
    policy=rr.load_json(ROOT/'rules/rmm_identity_profiles.json')
    import rmm_identity
    rmm_identity.rows(policy)
    constraint=rr.load_json(ROOT/'rules/rmm_identity_constraints.json')
    aliases={name.lower() for profile in policy['profiles'] for name in profile['names']}
    overrides={row['process_name']:row for row in constraint['overrides']}
    if constraint['schema_version']!=1 or len(overrides)!=len(constraint['overrides']) or set(overrides)-aliases:
        raise ValueError('Invalid or unowned identity constraint alias')
    records=[]
    for profile in policy['profiles']:
        for name in profile['names']:
            name=name.lower();override=overrides.get(name,{})
            if set(override)-{'process_name','tool_id','tool_name','signers','path_prefix','path_contains'}:
                raise ValueError('Unknown identity constraint property')
            signers=override.get('signers',profile['signers']);prefix=override.get('path_prefix','');contains=override.get('path_contains','')
            if not isinstance(signers,list) or any(not isinstance(s,str) or not s or any(c in s for c in ';\r\n*?') for s in signers):
                raise ValueError('Identity signers require exact nonempty tokens')
            tool_id=override.get('tool_id',profile['tool_id']);tool_name=override.get('tool_name',profile['tool_name'])
            if not re.fullmatch(r'[a-z0-9-]+',tool_id) or not isinstance(tool_name,str) or not tool_name:
                raise ValueError('Invalid identity tool ID or display name')
            if prefix and not prefix.endswith('/') or any(c in prefix+contains for c in '\r\n*?'):
                raise ValueError('Identity paths require literal directory constraints')
            aliases=sorted(set(profile['names'])|{Path(n).stem for n in profile['names']})
            records.append(dict(row_id=RELEASE+':'+name,record_type='profile',tool_id=tool_id,tool_name=tool_name,
                process_name=name,signers=';'+';'.join(sorted(set(s.lower() for s in signers)))+';',
                software_role=profile['role'],path_prefix=prefix,path_contains=contains,
                original_names=';'+';'.join(n.lower() for n in aliases)+';'))
    return seal(records,PROFILE_FIELDS)

def portable_value(field, value):
    value=rr.normalize(field,value)
    if field=='process_path' and re.match(r'^[a-zA-Z]:',str(value)):
        value=value.replace('\\','/')
    return str(value).lower() if type(value) is bool else str(value)

def regex_for(condition):
    field=condition['field'];op=condition['operator'];value=condition['value']
    pattern=rr.glob_regex(rr.normalize(field,value)) if op=='glob' else value
    if field=='process_path' and (pattern.startswith('^[a-z]:') or pattern.startswith('^c:')):
        pattern=pattern.replace('\\\\','/')
    key='rx-'+hashlib.sha256(pattern.encode()).hexdigest()[:16]
    return key,pattern

def policy_rows(policy=None, config=None, *, customer=False, release=RELEASE):
    defaults=rr.load_policy()
    if policy is None: policy=defaults[0]
    if config is None: config=defaults[1]
    if customer:
        source=[(r,'customer') for r in config.get('whitelist',[])]+[(r,'retain') for r in config.get('retain_rules',[])]
    else:
        source=[(r,'general') for r in policy['rules']]
        general=rr.load_json(ROOT/'rules/rmm_general_whitelist.json')
        for r in general['rules']: rr.validate_rule(r)
        source += [(r,'general_whitelist') for r in general['rules']]
    records=[]
    for rule,kind in source:
        if not rule['enabled']: continue
        for group_index,group in enumerate(rr.groups(rule)):
            group_id=rule['id']+':'+str(group_index)
            anchor=next((c for c in group if c['field'] in ('process_name','tool_id') and c['operator'] in ('equals','exact','in')),None)
            anchors=[('name:' if anchor['field']=='process_name' else 'tool:')+portable_value(anchor['field'],v)
                     for v in (anchor.get('values') or [anchor.get('value')])] if anchor else ['*']
            for anchor_index,anchor_key in enumerate(anchors):
                for index,condition in enumerate(group):
                    for value_index,value in enumerate(condition.get('values') or [condition.get('value')]):
                        if condition is anchor and anchor_key != ('name:' if anchor['field']=='process_name' else 'tool:')+portable_value(anchor['field'],value):
                            continue
                        op=condition['operator'];regex_key=''
                        if op in ('glob','regex'):
                            regex_key,_=regex_for(condition);stored='';op='regex'
                        else: stored=portable_value(condition['field'],value)
                        records.append(dict(row_id=f'{release}:{group_id}:{anchor_index}:{index}:{value_index}',record_type='condition',
                            rule_id=rule['id'],rule_kind=kind,rule_target=rule['target'],group_id=group_id,
                            condition_id=str(index),condition_count=str(len(group)),anchor_key=anchor_key,
                            field_name=condition['field'],operator='equals' if op=='in' else op,value=stored,regex_key=regex_key,
                            expires_at=rr.timestamp(rule['expires_at']).strftime('%Y-%m-%dT%H:%M:%SZ') if rule.get('expires_at') else ''))
    if customer:
        for rule_id in config.get('disabled_default_rules',[]):
            records.append(dict(row_id=release+':disabled:'+rule_id,record_type='disabled',rule_id=rule_id))
    return seal(records,POLICY_FIELDS,release)

def regex_pool(policy,config):
    general=rr.load_json(ROOT/'rules/rmm_general_whitelist.json')
    rules=policy['rules']+general['rules']+config.get('whitelist',[])+config.get('retain_rules',[])
    return dict(sorted({regex_for(c) for r in rules for g in rr.groups(r) for c in g if c['operator'] in ('glob','regex')}))

def write(check=False):
    entries=[('rmm_tool_profiles_v2.csv',profiles(),PROFILE_FIELDS),
             ('rmm_general_rules.csv',policy_rows(),POLICY_FIELDS)]
    for filename,records,fields in entries:
        validate(records,fields);target=ROOT/'data'/filename;payload=csv_bytes(records,fields)
        if check:
            if not target.exists() or target.read_bytes()!=payload: raise ValueError('Reference CSV is stale: '+filename)
        else: target.write_bytes(payload)
    return {filename:len(records)-1 for filename,records,_ in entries}

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true')
    print(json.dumps(write(parser.parse_args().check)))
