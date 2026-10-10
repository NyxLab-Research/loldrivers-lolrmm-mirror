import copy
import fnmatch
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import rmm_discovery as d
import rmm_reference_data as ref

class DiscoveryTests(unittest.TestCase):
    def setUp(self):self.rows=d.rows();self.process=[r for r in self.rows if r['record_type']=='process']
    def test_full_domain_feed_is_preserved_with_reviewed_alias_collapse(self):
        import csv
        with (ref.ROOT/'data/lolrmm_domains.csv').open(encoding='utf-8') as handle:upstream=list(csv.DictReader(handle))
        self.assertEqual({(r['domain'],r['pattern'].lower()) for r in upstream},
                         {(r['domain'],r['pattern']) for r in self.rows if r['record_type']=='domain'})
    def test_generic_and_colliding_names_never_become_process_evidence(self):
        self.assertTrue(d.GENERIC.isdisjoint({r['pattern'] for r in self.process}))
        source={'tools':[{'name':'Fictional A','patterns':['shared-fixture.exe','service.exe']},
                         {'name':'Fictional B','patterns':['shared-fixture.exe','service.exe']}]}
        records=[r for r in d.records(source) if r['record_type']=='process']
        self.assertEqual({r['software_role'] for r in records if r['pattern']=='shared-fixture.exe'},{'ambiguous'})
        self.assertNotIn('service.exe',{r['pattern'] for r in records})
    def test_missing_signer_tools_and_new_families_are_discoverable(self):
        for name in ('rustdesk.exe','aeroadmin.exe','meshagent.exe','dwagent.exe','rutserv.exe','anydesk-custom.exe'):
            self.assertTrue(any(fnmatch.fnmatchcase(name,r['pattern']) for r in self.process),name)
        self.assertFalse(any(fnmatch.fnmatchcase('anydesk.exe.evil',r['pattern']) for r in self.process))
    def test_catalog_does_not_grant_publisher_trust(self):
        self.assertNotIn('signers',d.FIELDS)
        self.assertEqual({r['tool_id'] for r in ref.profiles() if r['record_type']=='profile' and r['process_name']=='awesun.exe'},
                         {r['tool_id'] for r in self.process if r['pattern']=='awesun.exe'})
    def test_main_identity_aliases_have_same_tool_process_evidence(self):
        available={(r['pattern'],r['tool_id']) for r in self.process if r['anchor_key'].startswith('name:')}
        required={(r['process_name'],r['tool_id']) for r in ref.profiles() if r['record_type']=='profile'}
        self.assertTrue(required<=available,'Missing alias would require broad main discovery fallback')
    def test_native_matcher_input_is_bounded_to_one_star(self):
        for row in self.rows:
            if row['record_type']=='manifest':continue
            self.assertLessEqual(row['pattern'].count('*'),1)
            self.assertFalse(any(c in row['pattern'] for c in '?[]{}'))
    def test_inventory_components_stay_outside_remote_control_main(self):
        self.assertEqual({r['software_role'] for r in self.rows if r['tool_name']=='Freshservice'},{'management'})
    def test_release_digest_rejects_indicator_tampering(self):
        rows=copy.deepcopy(self.rows);rows[0]['pattern']='*'
        with self.assertRaises(ValueError):ref.validate(rows,d.FIELDS)

if __name__=='__main__':unittest.main()
