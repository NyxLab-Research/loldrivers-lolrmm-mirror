import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import rmm_domain_policy as p
import rmm_domain_queries as q
import rmm_reference_data as ref


def rule(ident,device):
    return dict(id=ident,reason='Synthetic test approval',enabled=True,target='activity',
                conditions=[dict(field='device_id',operator='equals',value=device)])

class CustomerMasterTests(unittest.TestCase):
    def source(self):
        return dict(schema_version=1,release='000001',customers={
            'customer-a':dict(whitelist=[rule('approved-device','device-a')],retain_rules=[],disabled_default_rules=[]),
            'customer-b':dict(whitelist=[],retain_rules=[],disabled_default_rules=[])})

    def test_empty_customer_has_own_marker_and_unknown_customer_fails(self):
        rows=p.customer_feed(self.source())
        empty=p.customer_rows('customer-b',rows)
        self.assertEqual(len(empty),1)
        self.assertEqual(empty[0]['expected_rows'],'0')
        with self.assertRaises(ValueError):p.customer_rows('typo',rows)

    def test_only_selected_customer_rules_reach_tenant(self):
        rows=p.customer_feed(self.source())
        a=p.customer_rows('customer-a',rows,release='000009')
        self.assertEqual({r['value'] for r in a if r['record_type']=='condition'},{'device-a'})
        self.assertEqual({r['release'] for r in a},{'000009'})
        ref.validate(a,ref.POLICY_FIELDS)
        self.assertEqual(len(p.customer_rows('customer-b',rows)),1)

    def test_moved_or_truncated_or_changed_customer_data_fails(self):
        rows=p.customer_feed(self.source())
        for damaged in (rows[1:], [dict(r,customer_id='customer-b') for r in rows],
                        [dict(r,value='tampered') if r['record_type']=='condition' else r for r in rows]):
            with self.assertRaises(ValueError):p.validate_customer_feed(damaged)

    def test_private_empty_customer_release_is_compatible(self):
        current=p.policy_rows(config={},customer=True,release='000001')
        self.assertEqual(current,p.customer_rows('customer-b',p.customer_feed(self.source())))

    def test_master_rejects_unknown_disabled_rule_and_unknown_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'customers.json'
            for mutate in ('disabled','unknown'):
                source=self.source()
                if mutate=='disabled':source['customers']['customer-b']['disabled_default_rules']=['unknown-rule']
                else:source['customers']['customer-b']['unexpected']=True
                path.write_text(json.dumps(source))
                with self.assertRaises(ValueError):p.load_customers(path)

    def test_cortex_refuses_mde_only_hash_rules(self):
        source=self.source()
        source['customers']['customer-a']['whitelist'][0]['conditions']=[dict(field='sha1',operator='equals',value='a'*40)]
        rows=p.customer_feed(source)
        with self.assertRaises(ValueError):p.customer_rows('customer-a',rows)
        self.assertEqual(len(p.customer_rows('customer-a',rows,platform='mde')),2)

    def test_native_mde_customer_rules_do_not_expand_query_text(self):
        text=q.build_mde('1h',customer_id='customer-a')
        self.assertIn('where customer_id==CustomerId',text)
        self.assertIn('GeneralOK and CustomerOK',text)
        self.assertIn('rule_id !in (Disabled)',text)
        self.assertIn('array_length(RetainRuleIds)>0',text)
        self.assertIn('array_length(CustomerWhitelistIds)==0',text)
        self.assertNotIn('approved-device',text)
        self.assertIn('let CustomerId="set-customer-id";',q.build_mde())

if __name__=='__main__':unittest.main()
