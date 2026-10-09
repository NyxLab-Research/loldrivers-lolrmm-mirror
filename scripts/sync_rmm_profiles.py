"""Stage, verify, then activate an approved Cortex identity release. Dry-run by default."""
import argparse
import json
import csv
import io
from pathlib import Path
import cortex_lookup as api
import rmm_identity as identity

SPEC=api.DatasetSpec('rmm_tool_profiles','rmm_tool_profiles.csv',identity.FIELDS,('profile_id',),'','')

def clean(rows):
    return [{k:str(r.get(k) or '') for k in identity.FIELDS} for r in rows]

def sync(client, desired, *, apply=False, limiter=None):
    marker=identity.validate_release(desired)
    release=marker['release']
    exists=SPEC.name in client.get_dataset_names()
    current=clean(client.get_rows(SPEC.name)) if exists else []
    same=[r for r in current if r['release']==release]
    active=[r for r in current if r['record_type']=='manifest']
    latest=max((r['release'] for r in active),default='')
    if latest>release:
        raise ValueError('Refusing release downgrade; remove a marker explicitly to roll back')
    if any(r['record_type']=='manifest' for r in same):
        identity.validate_release(same)
        if sorted(same,key=lambda r:r['profile_id'])!=sorted(desired,key=lambda r:r['profile_id']):
            raise ValueError('Published release is immutable; increment release')
        return {'status':'verified','release':release,'profiles':len(desired)-1}
    wanted={r['profile_id']:r for r in desired if r['record_type']=='profile'}
    staged={r['profile_id']:r for r in same}
    if len(staged)!=len(same) or any(k not in wanted or wanted[k]!=v for k,v in staged.items()):
        raise ValueError('Conflicting staged content; increment release or repair staging')
    missing=[r for k,r in wanted.items() if k not in staged]
    result={'status':'planned','release':release,'create_dataset':not exists,'stage_rows':len(missing),'previous_release':latest}
    if not apply: return result
    limiter=limiter or api.MutationLimiter(11)
    if not exists:
        limiter.run(lambda:client.add_dataset(SPEC))
        api.wait_for_dataset(client,SPEC.name)
    for batch in api.chunks(missing):
        limiter.run(lambda batch=batch:client.add_rows(SPEC,batch))
    staged=[r for r in clean(client.get_rows(SPEC.name)) if r['release']==release]
    identity.validate_release(staged+[marker])
    # The marker is the commit point. Never publish it before read-back validation.
    limiter.run(lambda:client.add_rows(SPEC,[marker]))
    final=[r for r in clean(client.get_rows(SPEC.name)) if r['release']==release]
    identity.validate_release(final)
    return dict(result,status='activated',profiles=len(final)-1)

def client_from_env(path):
    values=api.parse_env_file(path)
    if values.get('CORTEX_ENABLED','true').lower() in {'0','false','no'}:
        raise ValueError('Tenant is disabled')
    kind=values.get('CORTEX_API_KEY_TYPE','advanced').lower()
    if kind not in {'advanced','standard'}: raise ValueError('Invalid API key type')
    tenant=api.Tenant(values['CORTEX_TENANT_NAME'],api.validate_api_fqdn(values['CORTEX_API_FQDN']),
                      values['CORTEX_API_KEY_ID'],values['CORTEX_API_KEY'],kind)
    return api.CortexClient(tenant,90)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env',type=Path,required=True)
    parser.add_argument('--apply',action='store_true')
    parser.add_argument('--published',action='store_true',help='Read the approved CSV from GitHub instead of local rules')
    args=parser.parse_args()
    desired=published_rows() if args.published else identity.rows()
    print(json.dumps(sync(client_from_env(args.env),desired,apply=args.apply)))

def published_rows():
    url='https://raw.githubusercontent.com/NyxLab-Research/loldrivers-lolrmm-mirror/main/data/rmm_tool_profiles.csv'
    with api.urlopen(api.Request(url,headers={'User-Agent':'rmm-profile-sync/2'}),timeout=60) as response:
        payload=api.read_limited(response,2*1024*1024)
    reader=csv.DictReader(io.StringIO(payload.decode('utf-8-sig')))
    if tuple(reader.fieldnames or ())!=identity.FIELDS: raise ValueError('Invalid published profile schema')
    records=list(reader)
    identity.validate_release(records)
    return records

if __name__=='__main__': main()
