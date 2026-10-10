"""Private MDE customer filtering and final aggregation; no API or email calls."""
import argparse
import datetime as dt
import json
import re
from pathlib import Path
import rmm_domain_policy as policy
import rmm_domain_queries as queries
import rmm_report_rules as rr


def prepare_mde_query(query):
    """Keep matched general-excluded contexts so private retain/disable can restore them."""
    if query.count(queries.OUTPUT_MARKER) != 1:
        raise ValueError('Expected the current domain query output marker')
    return query.split(queries.OUTPUT_MARKER)[0] + queries.OUTPUT_MARKER + queries.mde_context_output()


def read_response(response):
    if not isinstance(response, dict) or response.get('error'):
        raise ValueError('Hunting API did not return a successful response')
    rows=response.get('results',response.get('Results'))
    if not isinstance(rows,list) or len(rows)>=100000 or any(response.get(k) for k in ('hasMoreResults','HasMoreResults','nextLink','@odata.nextLink')):
        raise ValueError('Missing or possibly truncated hunting results')
    schema=response.get('schema',response.get('Schema'))
    if not isinstance(schema,list) or {x.get('name',x.get('Name')) for x in schema} != set(queries.CONTEXT_FIELDS):
        raise ValueError('Customer filtering requires the context query schema, including an empty result')
    for row in rows:
        if not isinstance(row,dict) or row.get('ReportStatus')!='ok':
            raise ValueError('Reference health failed; do not deliver an empty successful report')
        if any(k not in row for k in queries.CONTEXT_FIELDS):
            raise ValueError('Incomplete context row')
        if not isinstance(row['GeneralRuleIds'],list) or not isinstance(row['GeneralWhitelistIds'],list):
            raise ValueError('General policy hits must be arrays')
        if any(not isinstance(x,str) for x in row['GeneralRuleIds']+row['GeneralWhitelistIds']):
            raise ValueError('Invalid general policy hit')
        if not row['DeviceId'] or not row['RemoteHost'] or not row['MatchedDomain'] or not row['Software']:
            raise ValueError('Context is missing domain/device identity')
        if type(row['EventCount']) is not int or row['EventCount']<1:
            raise ValueError('Invalid context event count')
    return rows


def instant(value):
    if not isinstance(value,str): raise ValueError('Missing context timestamp')
    date=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    if date.tzinfo is None: raise ValueError('Context timestamps require a timezone')
    return date.astimezone(dt.timezone.utc)


def time_key(value):
    fraction=re.search(r'\.(\d+)',value)
    return instant(value),int(fraction.group(1).ljust(9,'0')[:9]) if fraction else 0


def utc_text(value):
    fraction=re.search(r'\.(\d+)',value)
    return instant(value).strftime('%Y-%m-%dT%H:%M:%S')+('.'+fraction.group(1) if fraction else '')+'Z'


def finalize_mde_report(response, customer_path, expected_customer, now=None):
    """Call after complete API retrieval and before the existing Excel/export code."""
    p,c=policy.load_policy(customer_path)
    if not customer_path or c['customer_id']!=expected_customer:
        raise ValueError('A private rule file matching the execution customer is required')
    policy.validate_config(p,c,'mde')
    rows=read_response(response)
    now=now or dt.datetime.now(dt.timezone.utc)
    contexts={}; excluded=0
    for row in rows:
        normal={k:row[v] for k,v in {'device_id':'DeviceId','device_name':'DeviceName','process_name':'ProcessName',
            'process_path':'ProcessPath','sha1':'SHA1','sha256':'SHA256','remote_host':'RemoteHost',
            'matched_domain':'MatchedDomain','rmm_tool':'Software'}.items()}
        defaults=set(row['GeneralRuleIds'])-set(c.get('disabled_default_rules',[]))
        retained=any(rr.rule_matches(r,normal,now) for r in c.get('retain_rules',[]))
        whitelisted=bool(row['GeneralWhitelistIds']) or any(rr.rule_matches(r,normal,now) for r in c.get('whitelist',[]))
        if whitelisted or defaults and not retained:
            excluded+=1;continue
        key=tuple(row[k] for k in ('DeviceName','DeviceId','Software','ProcessName','ProcessPath','User','SHA1','SHA256','RemoteHost','RemoteIP'))
        first,last=time_key(row['FirstSeen']),time_key(row['LastSeen'])
        if first>last: raise ValueError('Inverted context timestamps')
        if key not in contexts: contexts[key]=dict(row,Domains=set(),First=first,Last=last,
                                                  FirstText=utc_text(row['FirstSeen']),LastText=utc_text(row['LastSeen']))
        context=contexts[key];context['Domains'].add(row['MatchedDomain'])
        if first<context['First']:context['First'],context['FirstText']=first,utc_text(row['FirstSeen'])
        if last>context['Last']:context['Last'],context['LastText']=last,utc_text(row['LastSeen'])
        context['EventCount']=max(context['EventCount'],row['EventCount'])
    groups={}
    for key,context in contexts.items():
        target=groups.setdefault((context['DeviceId'],context['Software']),dict(First=context['First'],Last=context['Last'],
            FirstText=context['FirstText'],LastText=context['LastText'],RemoteHosts=set(),RemoteIPs=set(),MatchedDomains=set(),EventCount=0,Latest=context,Key=key))
        if context['First']<target['First']:target['First'],target['FirstText']=context['First'],context['FirstText']
        if context['Last']>target['Last']:target['Last'],target['LastText']=context['Last'],context['LastText']
        for field,values in [('RemoteHosts',[context['RemoteHost']]),('RemoteIPs',[context['RemoteIP']]),('MatchedDomains',context['Domains'])]:
            target[field].update(v for v in values if v)
        target['EventCount']+=context['EventCount']
        if (context['Last'],key)>(target['Latest']['Last'],target['Key']):target['Latest'],target['Key']=context,key
    results=[]
    for (_,software),target in groups.items():
        latest=target['Latest'];out=dict(DeviceName=latest['DeviceName'],Software=software,
            LastSeen=target['LastText'],FirstSeen=target['FirstText'],
            RemoteHosts=sorted(target['RemoteHosts']),RemoteIPs=sorted(target['RemoteIPs']),MatchedDomains=sorted(target['MatchedDomains']),
            ProcessName=latest['ProcessName'],ProcessPath=latest['ProcessPath'],User=latest['User'],SHA256=latest['SHA256'],
            EventCount=target['EventCount'],ReportStatus='ok')
        results.append({key:out[key] for key in queries.REPORT_FIELDS})
    results.sort(key=lambda r:(time_key(r['LastSeen']),r['DeviceName'],r['Software']),reverse=True)
    return {'rows':results,'summary':{'customer':expected_customer,'contexts_received':len(rows),
        'contexts_excluded':excluded,'report_rows':len(results),'general_releases':sorted({r['GeneralRelease'] for r in rows})}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--response',type=Path,required=True)
    parser.add_argument('--customer',type=Path,required=True)
    parser.add_argument('--customer-id',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();target=args.output.resolve()
    if not any(target.is_relative_to(rr.ROOT/d) for d in ('output','tmp')):
        raise ValueError('Private report output must remain in output/ or tmp/')
    result=finalize_mde_report(rr.load_json(args.response),args.customer,args.customer_id)
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result['summary']))


if __name__=='__main__':main()
