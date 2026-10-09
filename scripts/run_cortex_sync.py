"""One private scheduled job for centralized RMM keys and an existing legacy sync."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tenant_credentials as creds

ROOT=Path(__file__).resolve().parents[1]

def write_legacy_keys(tenants,directory):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    if os.name=='posix':directory.chmod(0o700)
    expected={t.name+'.env' for t in tenants}
    for path in directory.glob('*.env'):
        if path.name not in expected:path.unlink()
    for tenant in tenants:
        values={'CORTEX_TENANT_NAME':tenant.name,'CORTEX_API_FQDN':tenant.api_fqdn,
                'CORTEX_API_KEY_ID':tenant.api_key_id,'CORTEX_API_KEY':tenant.api_key,
                'CORTEX_API_KEY_TYPE':tenant.api_key_type,'CORTEX_ENABLED':'true'}
        if any('\n' in value or '\r' in value for value in values.values()):
            raise ValueError('Credential values must be single-line; contents omitted')
        path=directory/(tenant.name+'.env');temporary=path.with_suffix('.pending')
        with os.fdopen(os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600),'w',encoding='utf-8') as file:
            file.write(''.join(key+'='+value+'\n' for key,value in values.items()))
        temporary.replace(path)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials',type=Path,required=True)
    parser.add_argument('--customer-dir',type=Path,required=True)
    parser.add_argument('--state-dir',type=Path,required=True)
    parser.add_argument('--legacy-script',type=Path)
    parser.add_argument('--legacy-tenant',action='append',default=[])
    args=parser.parse_args()
    tenants=creds.cortex_tenants(args.credentials,allow_shared=True)
    args.state_dir.mkdir(parents=True,exist_ok=True)
    if os.name=='posix':args.state_dir.chmod(0o700)
    result=subprocess.run([sys.executable,str(ROOT/'scripts/sync_rmm_references.py'),
        '--credentials',str(args.credentials),'--customer-dir',str(args.customer_dir),
        '--state-dir',str(args.state_dir/'rmm'),'--published','--apply']).returncode
    # Keep the existing LOLDrivers/legacy deployment scope; do not extend it implicitly.
    if args.legacy_script and args.legacy_tenant:
        selected=[t for t in tenants if t.name in args.legacy_tenant]
        if not selected:raise ValueError('No existing legacy tenant remains in the central configuration')
        directory=args.state_dir/'legacy_credentials'
        write_legacy_keys(selected,directory)
        legacy=subprocess.run([sys.executable,str(args.legacy_script),'--env-dir',str(directory)]).returncode
        result=max(result,legacy)
    raise SystemExit(result)

if __name__=='__main__':main()
