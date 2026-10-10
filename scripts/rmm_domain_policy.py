"""Current domain-report policy: data-only operators; no regex query registry."""
import csv
import re
import rmm_reference_data as ref
import rmm_report_rules as rr

RELEASE = '000002'
FIELDS = {'device_id', 'device_name', 'process_name', 'process_path', 'sha1',
          'sha256', 'remote_host', 'matched_domain', 'rmm_tool'}
OPERATORS = {'equals', 'exact', 'in', 'domain_suffix', 'path_prefix', 'contains', 'glob'}


def validate_config(policy, config, platform=None):
    general = rr.load_json(ref.ROOT / 'rules/rmm_general_whitelist.json')
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
    policy, config = rr.load_policy(ref.ROOT / 'rules/rmm_report_exclusions.json', customer_path)
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
    release = release or RELEASE
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
