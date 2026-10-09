"""Approved data-driven software identity. No tenant data or credentials."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ('profile_id','record_type','release','tool_id','tool_name','process_name','signers','software_role','ioc_names','expected_rows','release_digest')
GENERIC = {'agent.exe','client.exe','server.exe','setup.exe','updater.exe','java.exe','node.exe','python.exe','svchost.exe','chrome.exe','msedge.exe','firefox.exe','msedgewebview2.exe'}

def rows(policy=None):
    policy = policy or json.loads((ROOT/'rules/rmm_identity_profiles.json').read_text(encoding='utf-8'))
    if policy.get('schema_version') != 1 or not re.fullmatch(r'[0-9]{6}',policy.get('release','')):
        raise ValueError('Invalid identity schema/release')
    release=policy['release']
    result=[]
    names=set()
    tool_ids=set()
    for p in policy['profiles']:
        if p['tool_id'] in tool_ids or not re.fullmatch(r'[a-z0-9-]+',p['tool_id']):
            raise ValueError('Duplicate or invalid tool ID')
        tool_ids.add(p['tool_id'])
        if p['role'] not in {'rmm','management','dual_use'}:
            raise ValueError('Invalid software role')
        for key in ('names','signers','ioc_names'):
            if not isinstance(p[key],list) or any(not isinstance(v,str) or not v.strip() or any(c in v for c in ';\r\n\t*?') for v in p[key]):
                raise ValueError('Profiles require exact, printable tokens')
        for name in p['names']:
            name=name.lower()
            if name in names or name in GENERIC or '/' in name or '\\' in name:
                raise ValueError('Ambiguous or generic process alias: '+name)
            names.add(name)
            row=dict.fromkeys(FIELDS,'')
            row.update(profile_id=release+':'+name,record_type='profile',release=release,tool_id=p['tool_id'],
                       tool_name=p['tool_name'],process_name=name,signers=';'+';'.join(sorted(set(v.lower() for v in p['signers'])))+';',
                       software_role=p['role'],ioc_names=';'+';'.join(sorted(set(v.lower() for v in p['ioc_names'])))+';')
            result.append(row)
    if not result: raise ValueError('Empty identity release')
    result.sort(key=lambda r:r['profile_id'])
    digest=hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    for row in result:
        row.update(expected_rows=str(len(result)),release_digest=digest)
    marker=dict.fromkeys(FIELDS,'')
    marker.update(profile_id=release+':manifest',record_type='manifest',release=release,
                  expected_rows=str(len(result)),release_digest=digest)
    return result+[marker]

def csv_bytes(records):
    buf=io.StringIO(newline='')
    writer=csv.DictWriter(buf,fieldnames=FIELDS,lineterminator='\n')
    writer.writeheader();writer.writerows(records)
    return buf.getvalue().encode()

def validate_release(records):
    markers=[r for r in records if r['record_type']=='manifest']
    if len(markers)!=1: raise ValueError('Exactly one release marker required')
    marker=markers[0]
    profiles=[r for r in records if r['record_type']=='profile']
    if len(profiles)!=int(marker['expected_rows']) or len({r['process_name'] for r in profiles})!=len(profiles):
        raise ValueError('Incomplete or duplicate profile release')
    if any(r['release']!=marker['release'] or r['release_digest']!=marker['release_digest'] for r in profiles):
        raise ValueError('Mixed identity release')
    canonical=[dict(r,expected_rows='',release_digest='') for r in sorted(profiles,key=lambda r:r['profile_id'])]
    digest=hashlib.sha256(json.dumps(canonical,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    if digest!=marker['release_digest']: raise ValueError('Identity content digest mismatch')
    return marker

def classify(row, records=None):
    records=records or rows()
    profiles={p['process_name']:p for p in records if p['record_type']=='profile'}
    named=profiles.get(str(row.get('process_name') or '').lower())
    original=profiles.get(str(row.get('original_file_name') or '').lower())
    p=named or original
    conflict=bool(named and original and named['tool_id']!=original['tool_id'])
    if not p: return {'detected_tool':'','tool_id':'','evidence_level':'domain_only','identity_basis':'','software_role':''}
    signer=str(row.get('exclusion_signer',row.get('signer')) or '').lower()
    valid=row.get('exclusion_signature_valid',row.get('signature_valid')) is True
    supported=bool(signer and valid and ';'+signer+';' in p['signers'] and p['software_role']!='dual_use')
    return {'detected_tool':p['tool_name'],'tool_id':p['tool_id'],
            'evidence_level':'evidence_conflict' if conflict else 'supported_identity' if supported else 'software_candidate',
            'identity_basis':'conflicting_names' if conflict else 'file_name' if named else 'original_filename',
            'software_role':p['software_role']}

def candidates(catalog):
    """Propose exact aliases only. Proposals never activate publisher trust."""
    proposed=[]
    for tool in catalog:
        details=tool.get('Details') or {}
        pe=details.get('PEMetadata') or []
        if isinstance(pe,dict): pe=[pe]
        paths=details.get('InstallationPaths') or []
        if isinstance(paths,str): paths=[paths]
        values=paths+[p.get(k,'') for p in pe if isinstance(p,dict) for k in ('Filename','OriginalFileName')]
        for value in sorted({v for v in values if isinstance(v,str)}):
            name=re.split(r'[\\/]',value)[-1].lower()
            if name and name.endswith('.exe') and name not in GENERIC and not re.search(r'[*?<>%{}\[\];]',name):
                proposed.append({'tool':tool['Name'],'process_name':name,'status':'needs_review'})
    return sorted({(p['tool'],p['process_name']):p for p in proposed}.values(),key=lambda r:(r['tool'],r['process_name']))

def evaluate(policy, config, row, now=None):
    import rmm_report_rules as rr
    decision=rr.evaluate(policy,config,row,now)
    evidence=classify(row)
    noise=bool(evidence['tool_id'] and decision['default_rules'] and 'rpt-manageengine-endpointcentral' not in decision['default_rules'])
    activity=decision['customer_activity_rules']
    associations=decision['customer_association_rules']
    excluded=activity+associations+([] if noise or decision['retain_rules'] else decision['default_rules'])
    if noise: evidence['evidence_level']='evidence_conflict'
    reason=('customer_whitelist' if activity or associations else 'identity_noise_conflict' if noise else
            'report_scope_exclusion' if excluded and 'rpt-manageengine-endpointcentral' in excluded else
            'browser_report_scope' if excluded and 'rpt-browser-standard' in excluded else 'known_noise' if excluded else 'retained')
    return dict(decision,**evidence,excluded=bool(excluded),excluded_by=excluded,disposition_reason=reason)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--check',action='store_true')
    ap.add_argument('--catalog',type=Path)
    ap.add_argument('--refresh-proposals',action='store_true',help='Fetch upstream suggestions; never activate them')
    ap.add_argument('--proposals',type=Path,default=ROOT/'data/rmm_profile_candidates.json')
    args=ap.parse_args()
    records=rows();validate_release(records)
    target=ROOT/'data/rmm_tool_profiles.csv'
    payload=csv_bytes(records)
    if args.check:
        if not target.exists() or target.read_bytes()!=payload: raise ValueError('Identity CSV is stale')
    else: target.write_bytes(payload)
    if args.catalog or args.refresh_proposals:
        from sync_sources import fetch, write_bytes
        payload=args.catalog.read_bytes() if args.catalog else fetch('https://lolrmm.io/api/rmm_tools.json')
        catalog=json.loads(payload)
        if not isinstance(catalog,list) or not catalog or any(not isinstance(t,dict) or not isinstance(t.get('Name'),str) for t in catalog):
            raise ValueError('Invalid upstream catalog; previous proposals preserved')
        proposed=candidates(catalog)
        if not proposed: raise ValueError('Empty proposals; previous proposals preserved')
        write_bytes(args.proposals,(json.dumps(proposed,ensure_ascii=False,indent=2)+'\n').encode())
        write_bytes(args.proposals.with_name('rmm_profile_candidates_manifest.json'),(json.dumps({'source':'https://lolrmm.io/api/rmm_tools.json','source_sha256':hashlib.sha256(payload).hexdigest(),'tools':len(catalog),'proposals':len(proposed)},indent=2)+'\n').encode())
    print(json.dumps({'release':records[-1]['release'],'profiles':len(records)-1,'digest':records[-1]['release_digest']}))

if __name__=='__main__': main()
