"""Inventory, stage/read back, and activate RMM lookups using private YAML keys."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import URLError,HTTPError
from http.client import RemoteDisconnected,IncompleteRead
import time
import cortex_lookup as api
import rmm_reference_data as ref
import rmm_report_rules as rr
import tenant_credentials as creds
import rmm_domain_policy as domain

SPECS={key:api.DatasetSpec(name,name+'.csv',ref.fields(key),('row_id',),'','')
       for key,name in ref.REFERENCE_NAMES.items()}
DOMAIN_SPEC=api.DatasetSpec('lolrmm_domains','lolrmm_domains.csv',('domain','rmm_tool','pattern','regex'),('pattern','rmm_tool'),'','')

def published_references():
    def get(url):
        for attempt in range(3):
            try:
                with urlopen(Request(url,headers={'User-Agent':'nyx-rmm-reference-sync'}),timeout=30) as response:return api.read_limited(response)
            except (URLError,TimeoutError,RemoteDisconnected,IncompleteRead) as exc:
                if isinstance(exc,HTTPError) and exc.code not in (429,500,502,503,504):raise
                if attempt==2:raise
                time.sleep(3*(attempt+1))
    commit=json.loads(get('https://api.github.com/repos/NyxLab-Research/loldrivers-lolrmm-mirror/commits/main'))['sha']
    import re
    if not re.fullmatch(r'[a-f0-9]{40}',commit):raise ValueError('Invalid published source revision')
    base='https://raw.githubusercontent.com/NyxLab-Research/loldrivers-lolrmm-mirror/'+commit+'/data/'
    result={'commit':commit}
    for kind in ('general',):
        spec=SPECS[kind];reader=csv.DictReader(io.StringIO(get(base+spec.filename).decode('utf-8-sig')))
        if tuple(reader.fieldnames or ())!=spec.fields:raise ValueError('Published reference schema mismatch')
        rows=list(reader);ref.validate(rows,spec.fields);result[kind]=rows
    domain.validate_rows(result['general'])
    manifest=json.loads(get(base+'manifest.json'));payload=get(base+'lolrmm_domains.csv')
    if hashlib.sha256(payload).hexdigest()!=manifest['lolrmm_csv_sha256']:raise ValueError('Published domain content hash mismatch')
    reader=csv.DictReader(io.StringIO(payload.decode('utf-8-sig')))
    if tuple(reader.fieldnames or ())!=DOMAIN_SPEC.fields:raise ValueError('Published domain schema mismatch')
    result['domains']=list(reader)
    domain.validate_domains(result['domains'])
    if len(result['domains'])!=manifest['rmm_effective_rows']:raise ValueError('Published domain row count mismatch')
    return result

def sync_domains(client,exists,*,apply,limiter,desired=None):
    spec=DOMAIN_SPEC
    if desired is None:
        with (ref.ROOT/'data'/spec.filename).open(encoding='utf-8') as source:desired=list(csv.DictReader(source))
    desired=cleaned(desired,spec.fields)
    current=client.get_rows(spec.name) if exists else []
    if any(set(r)-set(spec.fields)-{'_time','_insert_time','_update_time','_collector_name','_collector_type'} for r in current):
        raise ValueError('Domain lookup contains unmanaged fields; inspect before updating')
    current=cleaned(current,spec.fields)
    def index(rows):
        result={tuple(r[k] for k in spec.key_fields):r for r in rows}
        if len(result)!=len(rows):raise ValueError('Duplicate domain key; inspect before updating')
        return result
    want,have=index(desired),index(current)
    stale=set(have)-set(want);upserts=[r for k,r in want.items() if have.get(k)!=r]
    if have and len(stale)/len(have)>.25:raise ValueError('Domain deletion guard exceeded')
    result={'create':not exists,'upserts':len(upserts),'delete':len(stale),'rows':len(desired),'status':'planned'}
    if not apply:return result
    if not exists:
        limiter.run(lambda:client.add_dataset(spec));api.wait_for_dataset(client,spec.name)
    replacements=set(have)&set(want)
    replacements={k for k in replacements if have[k]!=want[k]}
    for batch in api.chunks([dict(zip(spec.key_fields,key)) for key in replacements]):
        limiter.run(lambda batch=batch:client.remove_rows(spec,batch))
    for batch in api.chunks(upserts):limiter.run(lambda batch=batch:client.add_rows(spec,batch))
    for batch in api.chunks([dict(zip(spec.key_fields,key)) for key in stale]):
        limiter.run(lambda batch=batch:client.remove_rows(spec,batch))
    if index(cleaned(client.get_rows(spec.name),spec.fields))!=want:raise ValueError('Domain readback mismatch')
    return dict(result,status='verified')

def cleaned(rows,fields): return [{k:str(r.get(k) or '') for k in fields} for r in rows]

def sync_release(client,spec,desired,*,apply=False,limiter=None):
    marker=ref.validate(desired,spec.fields);release=marker['release']
    exists=spec.name in client.get_dataset_names()
    current=cleaned(client.get_rows(spec.name),spec.fields) if exists else []
    same=[r for r in current if r['release']==release]
    latest=max((r['release'] for r in current if r['record_type']=='manifest'),default='')
    if latest>release: raise ValueError('Release downgrade requires explicit rollback')
    if any(r['record_type']=='manifest' for r in same):
        ref.validate(same,spec.fields)
        if sorted(same,key=lambda r:r['row_id'])!=sorted(desired,key=lambda r:r['row_id']):
            raise ValueError('Published reference release is immutable')
        return {'status':'verified','release':release,'rows':len(desired)-1}
    wanted={r['row_id']:r for r in desired if r['record_type']!='manifest'}
    present={r['row_id']:r for r in same}
    if len(present)!=len(same) or any(k not in wanted or wanted[k]!=v for k,v in present.items()):
        raise ValueError('Conflicting staged rows; previous active reference preserved')
    missing=[v for k,v in wanted.items() if k not in present]
    result={'status':'planned','release':release,'create':not exists,'stage_rows':len(missing),'previous_release':latest}
    if not apply:return result
    limiter=limiter or api.MutationLimiter(11)
    if not exists:
        limiter.run(lambda:client.add_dataset(spec));api.wait_for_dataset(client,spec.name)
    for batch in api.chunks(missing):limiter.run(lambda batch=batch:client.add_rows(spec,batch))
    staged=[r for r in cleaned(client.get_rows(spec.name),spec.fields) if r['release']==release]
    ref.validate(staged+[marker],spec.fields)
    limiter.run(lambda:client.add_rows(spec,[marker]))
    final=[r for r in cleaned(client.get_rows(spec.name),spec.fields) if r['release']==release]
    ref.validate(final,spec.fields)
    # Keep three complete releases for rollback; bound lookup growth before the API read limit.
    retained=sorted({r['release'] for r in current+[marker] if r['record_type']=='manifest'},reverse=True)[:3]
    stale=[{'row_id':r['row_id']} for r in current if r['release'] not in retained and r['release']<release]
    for batch in api.chunks(stale):limiter.run(lambda batch=batch:client.remove_rows(spec,batch))
    return dict(result,status='activated',rows=len(desired)-1)

def customer_config(name,directory):
    path=Path(directory)/(name+'.json')
    if path.exists():
        config=domain.load_policy(path)[1]
        if config['customer_id']!=name:raise ValueError('Customer policy ID does not match the tenant alias')
        return config
    return {'schema_version':1,'customer_id':name,'disabled_default_rules':[],'retain_rules':[],'whitelist':[]}

def inventory(client):
    raw=api.unwrap_api_reply(client.post('/public_api/v1/xql/get_datasets',{}))
    if isinstance(raw,dict):raw=raw.get('data') or raw.get('datasets')
    if not isinstance(raw,list):raise api.SyncError('Invalid dataset inventory response')
    return {str(r.get('Dataset Name') or r.get('dataset_name') or '').lower():str(r.get('Type') or r.get('dataset_type') or '').lower() for r in raw}

def run_tenant(tenant,*,apply=False,customer_dir=None,output_dir=None,published=None):
    client=api.CortexClient(tenant,90);existing=inventory(client)
    result={'tenant':tenant.name,'existing_lookups':sorted(n for n,k in existing.items() if k=='lookup'),'references':{}}
    desired={'general':published['general'] if published else domain.policy_rows()}
    if published:result['source_commit']=published['commit']
    config=customer_config(tenant.name,customer_dir or ref.ROOT/'config/rmm_customers')
    domain.validate_config(domain.load_policy()[0],config,'cortex')
    # Determine the next revision from the tenant, so a lost local cache cannot overwrite a policy.
    release='000001'
    if SPECS['customer'].name in existing:
        current=cleaned(client.get_rows(SPECS['customer'].name),ref.POLICY_FIELDS)
        release=max((r['release'] for r in current if r['record_type']=='manifest'),default=release)
        active=[r for r in current if r['release']==release]
        if any(r['record_type']=='manifest' for r in active):
            ref.validate(active,ref.POLICY_FIELDS)
            candidate=domain.policy_rows(config=config,customer=True,release=release)
            if sorted(active,key=lambda r:r['row_id'])!=sorted(candidate,key=lambda r:r['row_id']):release=f'{int(release)+1:06d}'
    desired['customer']=domain.policy_rows(config=config,customer=True,release=release)
    if output_dir:
        target=Path(output_dir)/tenant.name;target.mkdir(parents=True,exist_ok=True)
        (target/'inventory_before.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        for key in desired:
            spec=SPECS[key]
            if spec.name in existing:
                if existing[spec.name]!='lookup':raise api.SyncError('Refusing to modify a non-lookup dataset')
                rows=client.get_rows(spec.name)
                (target/(spec.name+'_before.json')).write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
    limiter=api.MutationLimiter(11)
    for key,rows in desired.items():
        result['references'][key]=sync_release(client,SPECS[key],rows,apply=apply,limiter=limiter)
    # Provision/update only the project's domain lookup; unrelated lookups are untouched.
    spec=DOMAIN_SPEC
    if spec.name in existing and existing[spec.name]!='lookup':raise api.SyncError('Domain dataset has unexpected type')
    if output_dir and spec.name in existing:
        (target/(spec.name+'_before.json')).write_text(json.dumps(client.get_rows(spec.name),ensure_ascii=False,indent=2),encoding='utf-8')
    result['domains']=sync_domains(client,spec.name in existing,apply=apply,limiter=limiter,desired=published['domains'] if published else None)
    if output_dir:
        (target/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        if apply:(target/'customer_release.json').write_text(json.dumps({'release':release,'config_digest':rr.digest(config)}),encoding='utf-8')
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials',type=Path)
    parser.add_argument('--customer-dir',type=Path,default=ref.ROOT/'config/rmm_customers')
    parser.add_argument('--state-dir',type=Path,default=ref.ROOT/'output/rmm/sync')
    parser.add_argument('--tenant',action='append',default=[])
    parser.add_argument('--apply',action='store_true')
    parser.add_argument('--published',action='store_true',help='Pin approved public reference downloads to one GitHub commit')
    args=parser.parse_args();tenants=creds.cortex_tenants(args.credentials,allow_shared=True)
    unknown=set(args.tenant)-{t.name for t in tenants}
    if unknown:raise ValueError('Unknown or disabled customer selection')
    published=published_references() if args.published else None
    failures=[]
    seen=set()
    for tenant in tenants:
        if args.tenant and tenant.name not in args.tenant:continue
        if tenant.api_fqdn in seen:continue
        seen.add(tenant.api_fqdn)
        aliases=[t.name for t in tenants if t.api_fqdn==tenant.api_fqdn]
        try:
            if len(aliases)>1:
                policies=[customer_config(n,args.customer_dir) for n in aliases]
                if any(c.get('whitelist') or c.get('retain_rules') or c.get('disabled_default_rules') for c in policies):
                    raise ValueError('Shared API host: customer-specific scope must be resolved before enabling exclusions')
            result=run_tenant(tenant,apply=args.apply,customer_dir=args.customer_dir,output_dir=args.state_dir,published=published)
            result['tenant_aliases']=aliases
            print(json.dumps(result),flush=True)
        except Exception as exc:
            failures.append(tenant.name)
            print(json.dumps({'tenant':tenant.name,'status':'failed','error_type':type(exc).__name__,
                              'reason':str(exc) if isinstance(exc,ValueError) else 'API operation failed; sensitive details omitted'}),flush=True)
    if failures:raise SystemExit(1)

if __name__=='__main__':main()
