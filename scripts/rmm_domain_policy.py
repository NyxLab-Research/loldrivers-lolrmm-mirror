"""Current domain-report policy: data-only operators; no regex query registry."""
import csv
import re
import rmm_reference_data as ref
import rmm_report_rules as rr

GENERAL_SOURCE = ref.ROOT / 'rules/rmm_general_rules.json'
CUSTOMER_SOURCE = ref.ROOT / 'rules/rmm_customer_rules.json'
CUSTOMER_FIELDS = ('customer_id',) + ref.POLICY_FIELDS
RELEASE = '000002'
FIELDS = {'device_id', 'device_name', 'process_name', 'process_path', 'sha1',
          'sha256', 'remote_host', 'matched_domain', 'rmm_tool'}
OPERATORS = {'equals', 'exact', 'in', 'domain_suffix', 'path_prefix', 'contains', 'glob'}


def validate_config(policy, config, platform=None):
    general = {'rules': load_general()['whitelist']}
    complete = dict(schema_version=1, customer_id='default', disabled_default_rules=[], retain_rules=[], whitelist=[])
    complete.update(config)
    rr.validate_policy(policy, complete)
    ids = [r['id'] for r in policy['rules'] + general['rules'] + config.get('whitelist', []) + config.get('retain_rules', [])]
    if len(ids) != len(set(ids)): raise ValueError('Duplicate general/customer rule ID')
    for rule in policy['rules'] + general['rules'] + config.get('whitelist', []) + config.get('retain_rules', []):
        rr.validate_rule(rule)
        for group in rr.groups(rule):
            for c in group:
                if c['field'] not in FIELDS or c['operator'] not in OPERATORS:
                    raise ValueError('Domain report supports device/process/path/hash/host/tool conditions, without signature or identity fields')
                if platform == 'cortex' and c['field'] == 'sha1':
                    raise ValueError('Cortex customer rules require SHA256, not SHA1')
                if c['operator'] == 'glob' and (c['value'].count('*') > 1 or '?' in c['value']):
                    raise ValueError('Domain report glob supports at most one *; use AND contains/prefix conditions')
    return general


def load_policy(customer_path=None):
    policy, config = rr.load_policy(customer_path=customer_path)
    validate_config(policy, config)
    return policy, config


def policy_rows(policy=None, config=None, *, customer=False, release=None):
    if policy is None:
        policy, default = load_policy()
        if config is None: config = default
    config = config or {}
    general = validate_config(policy, config)
    sets = [(config.get('whitelist', []), 'customer'), (config.get('retain_rules', []), 'retain')] if customer else [
        (policy['rules'], 'general'), (general['rules'], 'general_whitelist')]
    release = release or load_general()['release']
    rows = []
    for rules, kind in sets:
        for rule in rules:
            if not rule['enabled']: continue
            for gi, group in enumerate(rr.groups(rule)):
                anchor = next((c for c in group if c['field'] in ('process_name', 'rmm_tool') and c['operator'] in ('equals', 'exact', 'in')), None)
                anchors = [(('name:' if anchor['field'] == 'process_name' else 'tool:') + ref.portable_value(anchor['field'], v))
                           for v in (anchor['values'] if anchor['operator'] == 'in' else [anchor['value']])] if anchor else ['*']
                for key in anchors:
                    for ci, c in enumerate(group):
                        values = c['values'] if c['operator'] == 'in' else [c['value']]
                        if c is anchor:
                            prefix='name:' if c['field']=='process_name' else 'tool:'
                            values=[v for v in values if prefix+ref.portable_value(c['field'],v)==key]
                        for vi, value in enumerate(values):
                            rows.append(dict(row_id=f'{release}:{kind}:{rule["id"]}:{gi}:{key}:{ci}:{vi}',
                                record_type='condition', release=release, rule_id=rule['id'], rule_kind=kind,
                                rule_target=rule['target'], group_id=f'{rule["id"]}:{gi}', condition_id=str(ci),
                                condition_count=str(len(group)), anchor_key=key, field_name=c['field'],
                                operator='equals' if c['operator'] == 'in' else c['operator'], value=ref.portable_value(c['field'], value),
                                regex_key='', expires_at=rr.timestamp(rule['expires_at']).strftime('%Y-%m-%dT%H:%M:%SZ') if rule.get('expires_at') else ''))
    if customer:
        rows += [dict(row_id=f'{release}:disabled:{rule}', record_type='disabled', release=release, rule_id=rule)
                 for rule in config.get('disabled_default_rules', [])]
    return ref.seal(rows, ref.POLICY_FIELDS, release)


def load_general(path=None):
    source = rr.load_json(path or GENERAL_SOURCE)
    if set(source) != {'schema_version','rule_version','release','rules','whitelist'} or not re.fullmatch(r'[0-9]{6}',str(source.get('release',''))):
        raise ValueError('Invalid general source schema or release')
    rr.validate_policy({k:source[k] for k in ('schema_version','rule_version','rules')},
                       dict(schema_version=1,customer_id='general',whitelist=source['whitelist']))
    return source


def load_customers(path=None):
    source = rr.load_json(path or CUSTOMER_SOURCE)
    if set(source) != {'schema_version','release','customers'} or source['schema_version'] != 1 or not re.fullmatch(r'[0-9]{6}',str(source['release'])):
        raise ValueError('Invalid customer master schema or release')
    if not isinstance(source['customers'],dict) or not source['customers']: raise ValueError('Customer registry is empty')
    policy,_ = load_policy()
    for name,config in source['customers'].items():
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,79}',name) or name=='set-customer-id': raise ValueError('Invalid customer code')
        if not isinstance(config,dict) or set(config) != {'disabled_default_rules','retain_rules','whitelist'}:
            raise ValueError('Invalid customer master entry')
        validate_config(policy,dict(config,schema_version=1,customer_id=name))
    return source


def customer_feed(source=None):
    source = source or load_customers()
    records = []
    for name, config in sorted(source['customers'].items()):
        rows = policy_rows(config=dict(config,schema_version=1,customer_id=name),customer=True,release=source['release'])
        raw=[dict(r,customer_id=name,row_id=name+':'+r['row_id']) for r in rows if r['record_type']!='manifest']
        sealed=ref.seal(raw,CUSTOMER_FIELDS,source['release'])
        sealed[-1]['customer_id']=name
        sealed[-1]['row_id']=name+':'+sealed[-1]['row_id']
        records.extend(sealed)
    validate_customer_feed(records)
    return records


def validate_customer_feed(rows):
    if not rows: raise ValueError('Empty customer feed')
    grouped={}
    for row in rows:
        name=row.get('customer_id','')
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,79}',name): raise ValueError('Invalid customer feed code')
        grouped.setdefault(name,[]).append(row)
    if len({r['release'] for r in rows})!=1: raise ValueError('Mixed customer feed releases')
    for name,group in grouped.items():
        ref.validate(group,CUSTOMER_FIELDS)
        if any(not r['row_id'].startswith(name+':') for r in group): raise ValueError('Customer row ownership mismatch')
        if any(r['record_type'] not in {'manifest','condition','disabled'} for r in group): raise ValueError('Unsupported customer record type')
        for r in group:
            if r['record_type']=='condition' and (r['rule_kind'] not in {'customer','retain'} or r['field_name'] not in FIELDS
                   or r['operator'] not in OPERATORS-{'in'} or r['regex_key'] or not r['value']):
                raise ValueError('Unsupported customer condition')
    return grouped


def customer_rows(name, rows=None, release='000001', platform='cortex'):
    grouped=validate_customer_feed(rows if rows is not None else customer_feed())
    if name not in grouped: raise ValueError('Customer code is not registered')
    raw=[]
    for row in grouped[name]:
        if row['record_type']=='manifest': continue
        if platform=='cortex' and row['field_name']=='sha1': raise ValueError('Cortex customer rules require SHA256')
        raw.append({k:row.get(k,'') for k in ref.POLICY_FIELDS})
    # Tenant-local releases remain independent from the public master release.
    for row in raw: row['row_id']=re.sub(r'^[^:]+:[0-9]{6}:',release+':',row['row_id'])
    return ref.seal(raw,ref.POLICY_FIELDS,release)


def validate_rows(rows):
    ref.validate(rows, ref.POLICY_FIELDS)
    for r in rows:
        if r['record_type'] == 'condition' and (r['field_name'] not in FIELDS or r['operator'] not in OPERATORS - {'in'}
                                             or r['regex_key'] or not r['value']):
            raise ValueError('Unsupported domain-report policy row')


def validate_domains(rows):
    if not rows: raise ValueError('Empty domain feed')
    for row in rows:
        if not row.get('domain') or not row.get('rmm_tool') or not row.get('pattern'):
            raise ValueError('Incomplete domain indicator')
        if row['pattern'].count('*') > 1 or any(c in row['pattern'] for c in '?[]{}'):
            raise ValueError('New domain pattern requires compatibility review')


def domain_rows():
    with (ref.ROOT / 'data/lolrmm_domains.csv').open(encoding='utf-8-sig') as handle:
        rows = list(csv.DictReader(handle))
    validate_domains(rows)
    return rows
