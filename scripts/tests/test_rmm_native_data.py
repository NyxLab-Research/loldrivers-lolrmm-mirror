import copy
from pathlib import Path
import sys
import unittest
import re
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import rmm_reference_data as ref
import rmm_report_rules as rr
import sync_rmm_references as sync
import tenant_credentials as creds

class Immediate:
    def run(self,fn):return fn()

class Fake:
    def __init__(self):self.data=[];self.calls=[];self.corrupt=False
    def get_dataset_names(self):return {sync.SPECS['profiles'].name}
    def get_rows(self,name):return copy.deepcopy(self.data)
    def add_rows(self,spec,rows):
        self.calls.append(copy.deepcopy(rows));self.data.extend(rows[:-1] if self.corrupt else rows)
    def remove_rows(self,spec,filters):
        ids={r['row_id'] for r in filters};self.data=[r for r in self.data if r['row_id'] not in ids]

class NativeDataTests(unittest.TestCase):
    def test_custom_and_or_survives_compilation(self):
        rule={'id':'approved-teamviewer','reason':'approved fixture','enabled':True,'target':'activity',
              'conditions':[{'field':'tool_id','operator':'equals','value':'teamviewer'},
                            {'field':'device_id','operator':'in','values':['device-a','device-b']}]}
        cfg={'whitelist':[rule]};rows=ref.policy_rows(config=cfg,customer=True)
        records=[r for r in rows if r['record_type']=='condition']
        self.assertEqual({r['anchor_key'] for r in records},{'tool:teamviewer'})
        self.assertEqual({r['condition_count'] for r in records},{'2'})
        self.assertEqual({r['value'] for r in records if r['field_name']=='device_id'},{'device-a','device-b'})
        self.assertNotEqual(ref.validate(rows,ref.POLICY_FIELDS)['release_digest'],
                            ref.validate(ref.policy_rows(config={},customer=True),ref.POLICY_FIELDS)['release_digest'])
    def test_marker_last_readback_and_idempotence(self):
        client=Fake();desired=ref.profiles()
        sync.sync_release(client,sync.SPECS['profiles'],desired,apply=True,limiter=Immediate())
        self.assertEqual(client.calls[-1][0]['record_type'],'manifest')
        self.assertTrue(all(r['record_type']=='profile' for r in client.calls[0]))
        sync.sync_release(client,sync.SPECS['profiles'],desired,apply=True,limiter=Immediate())
        self.assertEqual(len(client.calls),2)
    def test_partial_stage_never_activates(self):
        c=Fake();c.corrupt=True
        with self.assertRaises(ValueError):sync.sync_release(c,sync.SPECS['profiles'],ref.profiles(),apply=True,limiter=Immediate())
        self.assertFalse(any(r['record_type']=='manifest' for r in c.data))
    def test_profile_content_tamper_rejected(self):
        rows=ref.profiles();rows[0]['signers']=';attacker;'
        with self.assertRaises(ValueError):ref.validate(rows,ref.PROFILE_FIELDS)
    def test_empty_custom_is_valid_and_has_no_exclusions(self):
        rows=ref.policy_rows(config={},customer=True)
        self.assertEqual(len(rows),1);self.assertEqual(ref.validate(rows,ref.POLICY_FIELDS)['expected_rows'],'0')
    def test_compiled_general_rules_preserve_noise_boundaries(self):
        from test_rmm_scope import cases
        policy,config=rr.load_policy();data=ref.policy_rows();pool=ref.regex_pool(policy,config)
        for fixture in cases():
            matches={};required={}
            keys={'*','name:'+fixture['process_name'].lower()}
            for row in data:
                if row['record_type']!='condition' or row['anchor_key'] not in keys:continue
                field=row['field_name'];actual=fixture.get(field)
                if actual is None or actual=='':continue
                actual=ref.portable_value(field,actual)
                matched=(row['operator'] in ('equals','exact') and actual==row['value']) or (
                    row['operator']=='regex' and bool(re.search(pool[row['regex_key']],actual)))
                key=row['group_id'];required[key]=int(row['condition_count'])
                if matched:matches.setdefault(key,set()).add(row['condition_id'])
            excluded=any(len(value)==required[key] for key,value in matches.items())
            self.assertEqual(excluded,fixture['expected_excluded'],fixture['case_id'])
    def test_lookup_history_bounded_after_four_releases(self):
        client=Fake()
        for number in range(1,5):
            release=f'{number:06d}'
            rows=ref.seal([{'row_id':release+':fixture','record_type':'profile','tool_id':'fixture'}],ref.PROFILE_FIELDS,release)
            sync.sync_release(client,sync.SPECS['profiles'],rows,apply=True,limiter=Immediate())
        self.assertEqual({r['release'] for r in client.data},{'000002','000003','000004'})
    def test_credentials_repr_does_not_include_secrets(self):
        import cortex_lookup as api
        t=api.Tenant('fixture','fixture.paloaltonetworks.com','1','sensitive-fixture','standard')
        m=creds.MdeTenant('fixture','tenant','app','sensitive-fixture','app','other-sensitive')
        self.assertNotIn('sensitive-fixture',repr(t));self.assertNotIn('sensitive',repr(m))
    def test_unsupported_association_is_rejected_not_ignored(self):
        import rmm_native_queries as native
        policy,config=rr.load_policy()
        config['whitelist']=[{'conditions':[{'field':'matched_domain'}]}]
        with self.assertRaises(ValueError):native.check_config(policy,config)

if __name__=='__main__':unittest.main()
