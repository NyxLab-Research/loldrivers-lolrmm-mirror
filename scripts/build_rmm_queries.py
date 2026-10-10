"""Generate default or private customer RMM queries. No network/credential access."""
import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

import rmm_report_rules as rr

FIELDS = {
    'mde': {'device_id': 'DeviceId', 'device_name': 'RuleDeviceName', 'process_name': 'RuleName',
            'process_path': 'RulePath', 'sha1': 'RuleSHA1', 'sha256': 'RuleSHA256', 'signer': 'RuleSigner',
            'signature_valid': 'SignatureValid', 'remote_host': 'RemoteHost',
            'matched_domain': 'Domain', 'rmm_tool': 'RMMTool'},
    'cortex': {'device_id': 'agent_id', 'device_name': '_rule_device_name', 'process_name': '_rule_name',
               'process_path': '_rule_path', 'sha256': '_rule_sha256', 'signer': '_rule_signer',
               'signature_valid': '_signature_valid', 'remote_host': 'remote_host',
               'matched_domain': 'domain', 'rmm_tool': 'rmm_tool'}
}


def stages(policy, config, platform, mode):
    native = 'extend' if platform == 'mde' else 'alter'
    filt = 'where' if platform == 'mde' else 'filter'
    eq = '==' if platform == 'mde' else '='
    conditional = 'iff' if platform == 'mde' else 'if'
    defaults = [r for r in policy['rules'] if r['id'] not in config.get('disabled_default_rules', [])]
    whitelist = config.get('whitelist', [])
    if mode == 'baseline':
        defaults, whitelist, retains = [], [], []
    else:
        retains = config.get('retain_rules', [])
    activity = [r for r in whitelist if r['target'] == 'activity']
    associations = [r for r in whitelist if r['target'] == 'association']
    fields = FIELDS[platform]
    default_fields = dict(fields)
    if platform == 'mde':
        default_fields.update(signer='RuleEvidenceSigner', signature_valid='RuleEvidenceValid')
    activity_text = (f'| {native} DefaultRuleIds = {rr.compile_ids(defaults, platform, default_fields)},\n'
                     f'         RetainRuleIds = {rr.compile_ids(retains, platform, fields)},\n'
                     f'         CustomerActivityRuleIds = {rr.compile_ids(activity, platform, fields)}\n'
                     f'| {native} ActivityDecision = {conditional}((DefaultRuleIds != "" and RetainRuleIds {eq} "") or CustomerActivityRuleIds != "", "excluded", "retained")')
    # Activity fields no longer exist after comp. Reconstitute only when association rules need them.
    assoc_fields = dict(fields)
    if platform == 'mde':
        assoc_fields.update({'device_name': 'tolower(tostring(DeviceNames[0]))',
                             'process_name': 'tolower(InitiatingProcessFileName)',
                             'process_path': 'iff(InitiatingProcessFolderPath matches regex @"^[A-Za-z]:[\\/]", tolower(replace_string(InitiatingProcessFolderPath, "/", "\\")), InitiatingProcessFolderPath)',
                             'sha1': 'tolower(InitiatingProcessSHA1)', 'sha256': 'tolower(InitiatingProcessSHA256)'})
    else:
        assoc_fields.update({'device_name': 'lowercase(agent_hostname)', 'process_name': 'lowercase(actor_process_image_name)',
                             'process_path': r'if(actor_process_image_path ~= "^[A-Za-z]:", lowercase(replex(actor_process_image_path, "[\\\\]", "/")), actor_process_image_path)',
                             'sha256': 'lowercase(actor_process_image_sha256)'})
    # Signature conditions need per-event evidence, so they are restricted to activity rules.
    for rule in associations:
        if any(c['field'] in {'signer', 'signature_valid', 'device_name'} for g in rr.groups(rule) for c in g):
            raise ValueError(f'Association rule {rule["id"]}: signer/signature/device_name conditions require target=activity; use device_id for association scope')
    association_text = (f'| {native} CustomerAssociationRuleIds = {rr.compile_ids(associations, platform, assoc_fields)}\n'
                        f'| {native} AssociationDecision = {conditional}(CustomerAssociationRuleIds != "", "excluded", "retained")')
    meeting = rr.compile_condition({'field': 'process_path', 'operator': 'regex',
                                    'value': r'^[a-z]:.*\\wemeet\\wwmpapp[.]exe$'}, platform, fields)
    category = f'{conditional}({fields["process_name"]} {eq} "", "process_identity_missing", ' + \
               f'{conditional}({fields["process_name"]} {eq} "wwmpapp.exe" and {meeting}, "meeting_component_candidate", ' + \
               f'{conditional}({fields["remote_host"]} {eq} "oth.eve.mdt.qq.com", "shared_domain_activity", "rmm_domain_activity")))'
    return {'ACTIVITY_DECISIONS': activity_text, 'ASSOCIATION_DECISIONS': association_text,
            'REVIEW_CATEGORY': f'| {native} ReviewCategory = {category}',
            'ACTIVITY_FILTER': f'| {filt} ActivityDecision {eq} "retained"' if mode == 'report' else '',
            'ASSOCIATION_FILTER': f'| {filt} AssociationDecision {eq} "retained"' if mode == 'report' else ''}


def build(policy, config, platform, timeframe='7d', mode='report', source=None, view='all'):
    if not re.fullmatch(r'[1-9][0-9]*(?:m|h|d)', timeframe):
        raise ValueError('timeframe must be a positive integer followed by m/h/d')
    if mode not in {'report', 'audit', 'baseline'} or platform not in FIELDS:
        raise ValueError('Unsupported mode/platform')
    if view not in {'all', 'main', 'review'} or (view != 'all' and mode != 'report'):
        raise ValueError('main/review views require report mode')
    excluded_categories = ('meeting_component_candidate', 'process_identity_missing')
    view_filter = ''
    if view != 'all':
        op, join = ('!=', ' and ') if view == 'main' else ('==' if platform == 'mde' else '=', ' or ')
        view_filter = '| ' + ('where' if platform == 'mde' else 'filter') + ' ' + join.join(
            'ReviewCategory ' + op + ' ' + rr.quote(c) for c in excluded_categories)
    ext = 'kql' if platform == 'mde' else 'xql'
    template = (rr.ROOT / 'queries/templates' / f'lolrmm.{ext}.tmpl').read_text(encoding='utf-8')
    source = source or ('    externaldata(Domain:string, RMMTool:string, Pattern:string, Regex:string)\n'
                        '    [h\'https://raw.githubusercontent.com/NyxLab-Research/loldrivers-lolrmm-mirror/main/data/lolrmm_domains.csv\']\n'
                        '    with (format="csv", ignoreFirstRecord=true)')
    replacements = {'HEADER': f'// Generated by scripts/build_rmm_queries.py; rules {policy["rule_version"]}; mode {mode}; view {view}.\n'
                              f'// Rule SHA256: {rr.digest(policy)}; config SHA256: {rr.digest(config)}.\n'
                              '// Event counts precede IOC association; collection fields are independent sets.\n'
                              '// Official references and usage: README.md. Validate Cortex with a 1h window.',
                    'TIMEFRAME': timeframe, 'MDE_SOURCE': source,
                    'VIEW_FILTER': view_filter,
                    'MDE_HASH_SIGNATURE_FALLBACK': str(config.get('mde_hash_signature_fallback', True)).lower(),
                    'AUDIT_FIELDS': (',\n         ActivityDecision, AssociationDecision, DefaultRuleIds, RetainRuleIds,\n'
                                     '         CustomerActivityRuleIds, CustomerAssociationRuleIds') if mode != 'report' else '',
                    **stages(policy, config, platform, mode)}
    for name, value in replacements.items():
        template = template.replace('{{' + name + '}}', value)
    if '{{' in template:
        raise ValueError('Unresolved template token')
    if platform == 'cortex':
        executable = [line for line in template.splitlines() if line.strip() and not line.lstrip().startswith('//')]
        config_stages = [line for line in executable if re.match(r'^\s*(?:\|\s*)?config\b', line)]
        if len(config_stages) != 1 or not executable[0].startswith('config '):
            raise ValueError('Cortex config settings must share a single first stage')
    return template.rstrip() + '\n'


def main():
    import rmm_domain_policy as domain
    import rmm_domain_queries as queries
    parser=argparse.ArgumentParser(description='Generate the two current domain-only report queries')
    parser.add_argument('--customer',type=Path,help='Validate private rules; MDE emits customer-filter contexts')
    parser.add_argument('--platform',choices=['all','mde','cortex'],default='all')
    parser.add_argument('--timeframe',default='7d')
    parser.add_argument('--contexts',action='store_true',help='MDE contexts for the private customer adapter')
    parser.add_argument('--output-dir',type=Path)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    policy,config=domain.load_policy(args.customer)
    private=args.customer is not None or args.contexts or args.timeframe!='7d'
    output=(args.output_dir or rr.ROOT/('output/rmm/generated' if private else 'queries')).resolve()
    if private and not any(output.is_relative_to(rr.ROOT/d) for d in ('output','tmp')):
        raise ValueError('Customer/context/test queries must stay in private output/ or tmp/')
    platforms=['mde','cortex'] if args.platform=='all' else [args.platform]
    generated=[]
    for platform in platforms:
        domain.validate_config(policy,config,platform)
        text=queries.build_mde(args.timeframe,contexts=args.contexts or args.customer is not None) if platform=='mde' else queries.build_cortex(args.timeframe)
        path=output/platform/('lolrmm.kql' if platform=='mde' else 'lolrmm.xql')
        if args.check:
            if not path.exists() or path.read_text(encoding='utf-8')!=text:
                raise ValueError('Generated domain query is stale: '+str(path))
        else:
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(text,encoding='utf-8',newline='\n')
        print(('checked: ' if args.check else 'generated: ')+str(path))
        generated.append({'platform':platform,'sha256':hashlib.sha256(text.encode()).hexdigest()})
    if private and not args.check:
        (output/'rmm_generation_manifest.json').write_text(json.dumps({'schema_version':2,'logic':'domain_match',
            'timeframe':args.timeframe,'customer_id':config['customer_id'],'queries':generated},indent=2),encoding='utf-8')


if __name__=='__main__':
    try:main()
    except (ValueError,OSError) as exc:
        print('RMM query generation failed: '+str(exc),file=sys.stderr)
        raise SystemExit(1)
