"""Compile the two public rule sources and advance changed reference releases."""
import csv
import json
from pathlib import Path
import rmm_domain_policy as policy
import rmm_reference_data as ref


def refresh_source(path, feed, compile_rows, validate):
    source = json.loads(Path(path).read_text(encoding='utf-8'))
    requested = source['release']
    if Path(feed).exists():
        with Path(feed).open(encoding='utf-8-sig', newline='') as handle:
            previous = list(csv.DictReader(handle))
        validate(previous)
        releases = {row['release'] for row in previous}
        if len(releases) != 1:
            raise ValueError('Expected one published feed release')
        old = releases.pop()
        candidate = compile_rows(dict(source, release=old))
        changed = sorted(candidate, key=lambda r: r['row_id']) != sorted(previous, key=lambda r: r['row_id'])
        source['release'] = f'{max(int(requested), int(old) + int(changed)):06d}'
        if len(source['release']) != 6:
            raise ValueError('Reference release range exhausted')
    if source['release'] != requested:
        Path(path).write_text(json.dumps(source, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return source['release']


def main():
    policy.load_general()
    policy.load_customers()
    general = refresh_source(policy.GENERAL_SOURCE, ref.ROOT/'data/rmm_general_rules.csv',
        lambda source: policy.policy_rows(policy={k: source[k] for k in ('schema_version','rule_version','rules')},
                                         release=source['release']), policy.validate_rows)
    customer = refresh_source(policy.CUSTOMER_SOURCE, ref.ROOT/'data/rmm_customer_rules.csv',
                              policy.customer_feed, policy.validate_customer_feed)
    ref.write()
    print(json.dumps(dict(general_release=general, customer_release=customer)))


if __name__ == '__main__':
    main()
