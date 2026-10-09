"""Shared RMM report rule validation, native expression compilation and offline review.

No credentials or API calls. Conditions are ANDed; alternatives/rules are ORed.
Windows names/paths are case insensitive; Unix paths retain their case.
"""
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
FIELDS = {'device_id', 'device_name', 'process_name', 'process_path', 'sha1',
          'sha256', 'signer', 'signature_valid', 'remote_host', 'matched_domain', 'rmm_tool'}
ASSOCIATION_FIELDS = {'matched_domain', 'rmm_tool'}
OPERATORS = {'equals', 'exact', 'in', 'domain_suffix', 'path_prefix', 'glob', 'regex'}
CASE_INSENSITIVE = {'device_name', 'process_name', 'sha1', 'sha256', 'signer', 'remote_host', 'matched_domain'}
DOMAIN_RE = re.compile(r'^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$')


def load_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f'Duplicate JSON key: {key}')
            result[key] = value
        return result
    return json.loads(Path(path).read_text(encoding='utf-8-sig'), object_pairs_hook=unique)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode()).hexdigest()


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('expires_at must be an ISO timestamp with timezone or null')
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None or parsed.microsecond:
        raise ValueError('expires_at requires a timezone and whole seconds')
    return parsed.astimezone(dt.timezone.utc)


def normalize(field, value):
    if value is None:
        return None
    if field == 'signature_valid':
        return value if type(value) is bool else None
    if not isinstance(value, str):
        return None
    if field in CASE_INSENSITIVE:
        value = value.lower()
    if field in {'remote_host', 'matched_domain'}:
        value = value.rstrip('.')
    if field == 'process_path' and re.match(r'^[a-zA-Z]:[\\/]', value):
        value = value.replace('/', '\\').lower()
    return value


def remote_host(value):
    """Handle URLs, FQDNs, host:port and protocol-relative URLs consistently."""
    if not value or not isinstance(value, str):
        return ''
    try:
        parsed = urlsplit('https:' + value if value.startswith('//') else
                          value if '://' in value else 'https://' + value)
        return (parsed.hostname or '').lower().rstrip('.')
    except ValueError:
        return ''


def glob_regex(value):
    if '[' in value or ']' in value:
        raise ValueError('glob supports only * and ?; use an exact path for brackets')
    return '^' + ''.join('.*' if c == '*' else '.' if c == '?' else re.escape(c)
                         for c in value) + '$'


def validate_condition(condition, target, *, trusted=False):
    if not isinstance(condition, dict):
        raise ValueError('A condition must be an object')
    if set(condition) - {'field', 'operator', 'value', 'values'}:
        raise ValueError('Unknown condition keys')
    field, op = condition.get('field'), condition.get('operator')
    if field not in FIELDS or op not in OPERATORS:
        raise ValueError(f'Unsupported field/operator: {field}/{op}')
    if target == 'activity' and field in ASSOCIATION_FIELDS:
        raise ValueError('IOC-domain/tool conditions require target=association')
    if target == 'association' and field in {'signer', 'signature_valid', 'device_name'}:
        raise ValueError('Signer/signature/device-name conditions require target=activity; use device_id for association scope')
    if op == 'regex' and not trusted:
        raise ValueError('Customer rules use exact/in/suffix/path_prefix/glob, not raw regex')
    expected_key = 'values' if op == 'in' else 'value'
    if expected_key not in condition or ('value' in condition and 'values' in condition):
        raise ValueError('Use value, or a nonempty values array for in')
    vals = condition[expected_key] if op == 'in' else [condition[expected_key]]
    if not isinstance(vals, list) or not vals:
        raise ValueError('Empty condition values are not permitted')
    for val in vals:
        if field == 'signature_valid':
            if type(val) is not bool or op not in {'equals', 'in'}:
                raise ValueError('signature_valid expects boolean equals/in')
            continue
        if not isinstance(val, str) or not val.strip() or any(ord(c) < 32 for c in val):
            raise ValueError('Condition values must be nonempty printable strings')
        if len(val) > 2048:
            raise ValueError('Condition value too long')
        if field in {'sha1', 'sha256'} and not re.fullmatch(
                r'[a-fA-F0-9]{%d}' % (40 if field == 'sha1' else 64), val):
            raise ValueError(f'Invalid {field}')
        if field in {'remote_host', 'matched_domain'} and op != 'regex' and not DOMAIN_RE.fullmatch(normalize(field, val)):
            raise ValueError('Domain conditions require a host, without URL, port or wildcard')
        if op == 'regex':
            if re.search(r'\(\?[=!<]|\\[1-9]', val):
                raise ValueError('Regex must be portable to RE2 (no lookaround/backreferences)')
            re.compile(val)
        if op == 'glob':
            glob_regex(val)
    if op == 'domain_suffix' and field not in {'remote_host', 'matched_domain'}:
        raise ValueError('domain_suffix only supports domain fields')
    if op in {'path_prefix', 'glob'} and field != 'process_path':
        raise ValueError('path_prefix/glob only support process_path')
    if op == 'path_prefix' and any(not v.endswith(('\\', '/')) for v in vals):
        raise ValueError('path_prefix must end at a directory separator')
    if field in {'sha1', 'sha256', 'signature_valid'} and op not in {'equals', 'exact', 'in'}:
        raise ValueError('Hash/boolean conditions require equality/in')


def validate_rule(rule, *, trusted=False):
    keys = {'id', 'reason', 'enabled', 'target', 'expires_at', 'conditions', 'alternatives'}
    if not isinstance(rule, dict) or set(rule) - keys:
        raise ValueError('Invalid rule object or unknown keys')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,79}', rule.get('id', '')):
        raise ValueError('Rule ID must use lowercase letters, digits and hyphens')
    if not isinstance(rule.get('reason'), str) or not rule['reason'].strip():
        raise ValueError('Rule reason is required')
    if type(rule.get('enabled')) is not bool or rule.get('target') not in {'activity', 'association'}:
        raise ValueError('Rule needs enabled boolean and target')
    if rule.get('expires_at') is not None:
        timestamp(rule['expires_at'])
    if ('conditions' in rule) == ('alternatives' in rule):
        raise ValueError('Use either conditions (AND) or alternatives (OR of AND lists)')
    groups = [rule['conditions']] if 'conditions' in rule else rule['alternatives']
    if not isinstance(groups, list) or not groups:
        raise ValueError('Empty rules are not permitted')
    for group in groups:
        if not isinstance(group, list) or not group:
            raise ValueError('Empty alternatives are not permitted')
        for c in group:
            validate_condition(c, rule['target'], trusted=trusted)
        if rule['target'] == 'association' and not any(c['field'] in ASSOCIATION_FIELDS for c in group):
            raise ValueError('Association rules require a matched_domain or rmm_tool condition')


def load_policy(rules_path=None, customer_path=None):
    policy = load_json(rules_path or ROOT / 'rules/rmm_report_exclusions.json')
    if set(policy) - {'schema_version', 'rule_version', 'rules'} or type(policy.get('schema_version')) is not int or policy.get('schema_version') != 1:
        raise ValueError('Unsupported policy schema')
    if not re.fullmatch(r'\d+\.\d+\.\d+', policy.get('rule_version', '')):
        raise ValueError('rule_version must be a semantic version')
    if not isinstance(policy.get('rules'), list):
        raise ValueError('rules must be an array')
    config = load_json(customer_path) if customer_path else {
        'schema_version': 1, 'customer_id': 'default', 'disabled_default_rules': [],
        'retain_rules': [], 'whitelist': []}
    if set(config) - {'schema_version', 'customer_id', 'disabled_default_rules', 'retain_rules', 'whitelist', 'mde_hash_signature_fallback'} or type(config.get('schema_version')) is not int or config.get('schema_version') != 1:
        raise ValueError('Unsupported customer schema or unknown keys')
    if type(config.get('mde_hash_signature_fallback', True)) is not bool:
        raise ValueError('mde_hash_signature_fallback must be boolean')
    if not isinstance(config.get('customer_id'), str) or not config['customer_id'].strip():
        raise ValueError('customer_id required')
    ids = set()
    for rule in policy['rules']:
        validate_rule(rule, trusted=True)
        if rule['id'] in ids:
            raise ValueError('Duplicate rule ID')
        ids.add(rule['id'])
    disabled = config.get('disabled_default_rules', [])
    if not isinstance(disabled, list) or any(not isinstance(x, str) for x in disabled) or set(disabled) - ids or len(disabled) != len(set(disabled)):
        raise ValueError('Unknown disabled default rule ID')
    for kind in ('retain_rules', 'whitelist'):
        rules = config.get(kind, [])
        if not isinstance(rules, list):
            raise ValueError(f'{kind} must be an array')
        for rule in rules:
            validate_rule(rule)
            if kind == 'retain_rules' and rule['target'] != 'activity':
                raise ValueError('Retain overrides must target activity')
            if rule['id'] in ids:
                raise ValueError('Duplicate rule ID across policy/customer config')
            ids.add(rule['id'])
    retains = {digest({k: r.get(k) for k in ('target', 'conditions', 'alternatives', 'expires_at')})
               for r in config.get('retain_rules', []) if r['enabled']}
    if any(digest({k: r.get(k) for k in ('target', 'conditions', 'alternatives', 'expires_at')}) in retains
           for r in config.get('whitelist', []) if r['enabled']):
        raise ValueError('Identical retain and whitelist conditions conflict')
    return policy, config


def supports(rule, platform):
    fields = {c['field'] for group in groups(rule) for c in group}
    return not (platform == 'cortex' and 'sha1' in fields)


def groups(rule):
    return [rule['conditions']] if 'conditions' in rule else rule['alternatives']


def condition_matches(c, row):
    field, op = c['field'], c['operator']
    actual = row.get(field)
    if isinstance(actual, list):
        # Aggregated signature evidence must agree, not match just one element.
        return bool(actual) and all(condition_matches(c, {field: x}) for x in actual)
    actual = normalize(field, actual)
    if actual is None or actual == '':
        return False
    values = c['values'] if op == 'in' else [c['value']]
    for value in values:
        value = normalize(field, value) if op != 'regex' else value
        if op in {'equals', 'exact', 'in'} and actual == value:
            return True
        if op == 'domain_suffix' and (actual == value or actual.endswith('.' + value)):
            return True
        if op == 'path_prefix' and actual.startswith(value):
            return True
        if op in {'regex', 'glob'} and re.search(glob_regex(value) if op == 'glob' else value, actual):
            return True
    return False


def rule_matches(rule, row, now=None):
    if not rule['enabled']:
        return False
    if rule.get('expires_at') and (now or dt.datetime.now(dt.timezone.utc)) >= timestamp(rule['expires_at']):
        return False
    return any(all(condition_matches(c, row) for c in group) for group in groups(rule))


def evaluate(policy, config, row, now=None):
    default_row = dict(row)
    if config.get('mde_hash_signature_fallback', True) and row.get('signature_evidence_source') == 'tenant_sha1' and row.get('signature_valid') is None:
        default_row['signer'] = row.get('exclusion_signer')
        default_row['signature_valid'] = row.get('exclusion_signature_valid')
    defaults = [r['id'] for r in policy['rules'] if r['id'] not in config.get('disabled_default_rules', []) and rule_matches(r, default_row, now)]
    retains = [r['id'] for r in config.get('retain_rules', []) if rule_matches(r, row, now)]
    activity = [r['id'] for r in config.get('whitelist', []) if r['target'] == 'activity' and rule_matches(r, row, now)]
    associations = [r['id'] for r in config.get('whitelist', []) if r['target'] == 'association' and rule_matches(r, row, now)]
    excluded = activity + ([] if retains else defaults) + associations
    return {'excluded': bool(excluded), 'default_rules': defaults, 'retain_rules': retains,
            'customer_activity_rules': activity, 'customer_association_rules': associations,
            'excluded_by': excluded}


def certificate_evidence(row, local=None, observations=(), allow_fallback=True):
    """Resolve report identity evidence; never replace a local certificate record.

    Observations must be tenant-local, within the query's certificate window.
    Caller supplies the latest local record. All matching hash observations must
    agree on a nonempty signer and be signed/trusted before a fallback is usable.
    """
    result = dict(row, signature_evidence_source='missing', exclusion_signer=None,
                  exclusion_signature_valid=None, signature_evidence_device_id=None,
                  signature_evidence_time=None)
    if local is not None:
        signed, trusted = local.get('IsSigned'), local.get('IsTrusted')
        result.update(signer=local.get('Signer'),
                      signature_valid=(signed and trusted) if type(signed) is bool and type(trusted) is bool else None,
                      signature_evidence_source='device_sha1',
                      signature_evidence_device_id=local.get('DeviceId'), signature_evidence_time=local.get('Timestamp'))
        return result
    sha1 = normalize('sha1', row.get('sha1'))
    if not allow_fallback or not sha1 or not re.fullmatch('[a-f0-9]{40}', sha1):
        return result
    candidates = [o for o in observations if normalize('sha1', o.get('SHA1')) == sha1]
    if not candidates or any(o.get('IsSigned') is not True or o.get('IsTrusted') is not True
                             or not (o.get('Signer') or '').strip() for o in candidates):
        return result
    if len({normalize('signer', o['Signer']) for o in candidates}) != 1:
        return result
    latest = max(candidates, key=lambda o: o['Timestamp'])
    result.update(signature_evidence_source='tenant_sha1', exclusion_signer=latest['Signer'],
                  exclusion_signature_valid=True, signature_evidence_device_id=latest['DeviceId'],
                  signature_evidence_time=latest['Timestamp'])
    return result


def review_category(row):
    name = normalize('process_name', row.get('process_name')) or ''
    path = normalize('process_path', row.get('process_path')) or ''
    if not name:
        return 'process_identity_missing'
    if name == 'wwmpapp.exe' and re.search(r'^[a-z]:.*\\wemeet\\wwmpapp[.]exe$', path):
        return 'meeting_component_candidate'
    if normalize('remote_host', row.get('remote_host')) == 'oth.eve.mdt.qq.com':
        return 'shared_domain_activity'
    return 'rmm_domain_activity'


def quote(value, platform='mde'):
    return json.dumps(value, ensure_ascii=True)


def quote_regex(value, platform):
    # XQL regex literals preserve backslashes; KQL string literals unescape them.
    if platform == 'cortex':
        return '"' + value.replace('"', '\\"') + '"'
    return quote(value)


def compile_condition(c, platform, fields):
    field, op = c['field'], c['operator']
    expr = fields[field]
    vals = c['values'] if op == 'in' else [c['value']]
    predicates = []
    for val in vals:
        val = normalize(field, val) if op != 'regex' else val
        windows_path = field == 'process_path' and (bool(re.match(r'^[a-zA-Z]:', str(val))) or
                                                    (op == 'regex' and str(val).startswith('^[a-z]:')))
        if platform == 'cortex' and windows_path and op != 'regex':
            val = val.replace('\\', '/')
        literal = str(val).lower() if type(val) is bool else quote(val, platform)
        eq = '==' if platform == 'mde' else '='
        if op in {'equals', 'exact', 'in'}:
            pred = f'{expr} {eq} {literal}'
        elif op == 'domain_suffix':
            pred = (f'({expr} == {literal} or {expr} endswith {quote("." + val)})' if platform == 'mde'
                    else f'({expr} = {literal} or wildcard_match({expr}, {quote("*." + val, platform)}))')
        else:
            pattern = ('^' + re.escape(val)) if op == 'path_prefix' else glob_regex(val) if op == 'glob' else val
            if platform == 'cortex' and windows_path:
                pattern = pattern.replace('\\\\', '/')
            pred = f'{expr} {"matches regex" if platform == "mde" else "~="} {quote_regex(pattern, platform)}'
        # Missing fields never satisfy a condition, including false signature checks.
        guard = (f'isnotnull({expr})' if field == 'signature_valid' else f'isnotempty({expr})') if platform == 'mde' else f'{expr} != null'
        if platform == 'cortex' and field != 'signature_valid':
            guard += f' and {expr} != ""'
        predicates.append(f'({guard} and ({pred}))')
    return '(' + ' or '.join(predicates) + ')'


def compile_rule(rule, platform, fields):
    if not rule['enabled']:
        return 'false'
    if not supports(rule, platform):
        raise ValueError(f'Rule {rule["id"]}: SHA1 is unavailable in Cortex Actor schema')
    body = '(' + '\n            or '.join('(' + '\n                and '.join(compile_condition(c, platform, fields) for c in group) + ')'
                            for group in groups(rule)) + ')'
    if rule.get('expires_at'):
        expiry = timestamp(rule['expires_at']).strftime('%Y-%m-%dT%H:%M:%SZ')
        active = (f'now() < datetime({expiry})' if platform == 'mde' else
                  f'current_time() < parse_timestamp("%Y-%m-%dT%H:%M:%SZ", {quote(expiry, platform)}, "UTC")')
        body = f'({active} and {body})'
    return body


def compile_ids(rules, platform, fields):
    parts = []
    for rule in sorted(rules, key=lambda r: r['id']):
        if not rule['enabled']:
            continue
        expression = compile_rule(rule, platform, fields)
        parts.append(f'{"iff" if platform == "mde" else "if"}({expression}, {quote(rule["id"] + ";", platform)}, "")')
    return ('strcat' if platform == 'mde' else 'concat') + '(' + ',\n         '.join(parts) + ')' if parts else '""'


def identity(row):
    return tuple(normalize(k, row.get(k)) or '' for k in
                 ('device_id', 'remote_host', 'process_name', 'process_path', 'sha1', 'sha256'))


def review_rows(rows, policy, config, now=None):
    """Review existing exports without queries; merge domains without summing duplicate events."""
    reviewed, activities = [], {}
    for row in rows:
        row = dict(row)
        count = row.get('event_count')
        if isinstance(count, bool) or not re.fullmatch(r'[0-9]+', str(count)):
            raise ValueError('event_count must be a nonnegative integer')
        row['event_count'] = int(count)
        if isinstance(row.get('rmm_tool'), list) and any(c['field'] == 'rmm_tool' for r in config.get('whitelist', []) if r['target'] == 'association' for g in groups(r) for c in g):
            raise ValueError('Split tool labels into scalar associations before a tool-scoped whitelist preview')
        decision = evaluate(policy, config, row, now)
        reviewed.append({**row, **decision})
        key = identity(row)
        state = activities.setdefault(key, {'event_count': row.get('event_count', 0), 'rows': []})
        if state['event_count'] != row.get('event_count', 0):
            raise ValueError('Inconsistent event counts for duplicate activity associations')
        state['rows'].append(reviewed[-1])
    retained = [s for s in activities.values() if any(not r['excluded'] for r in s['rows'])]
    return {'summary': {'input_associations': len(rows), 'excluded_associations': sum(r['excluded'] for r in reviewed),
                        'unique_activities': len(activities), 'retained_activities': len(retained),
                        'retained_events': sum(s['event_count'] for s in retained),
                        'rule_version': policy['rule_version'], 'policy_sha256': digest(policy),
                        'config_sha256': digest(config)},
            'rules_snapshot': policy, 'customer_snapshot': config,
            'rows': reviewed}
