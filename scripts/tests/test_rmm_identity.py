"""Evidence boundaries and version completeness, using fictional rows only."""
import copy
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import rmm_identity as identity
import sync_sources as sources
import rmm_report_rules as rr
import build_rmm_queries as bq
import build_rmm_identity_queries as iq

class IdentityTests(unittest.TestCase):
    def test_missing_signature_is_candidate_not_negative(self):
        row={'process_name':'teamviewer_service.exe','signer':None,'signature_valid':None}
        self.assertEqual(identity.classify(row)['evidence_level'],'software_candidate')
        row.update(signer='TeamViewer Germany GmbH',signature_valid=True)
        self.assertEqual(identity.classify(row)['evidence_level'],'supported_identity')
        row['signature_valid']=False
        self.assertEqual(identity.classify(row)['evidence_level'],'software_candidate')

    def test_rename_dual_use_and_conflict(self):
        row={'process_name':'renamed.exe','original_file_name':'anydesk.exe','signer':'AnyDesk Software GmbH','signature_valid':True}
        self.assertEqual(identity.classify(row)['identity_basis'],'original_filename')
        row['process_name']='teamviewer.exe'
        self.assertEqual(identity.classify(row)['evidence_level'],'evidence_conflict')
        qq={'process_name':'qq.exe','signer':'Tencent Technology (Shenzhen) Company Limited','signature_valid':True}
        self.assertEqual(identity.classify(qq)['evidence_level'],'software_candidate')
        self.assertEqual(identity.classify(dict(row,process_name='agent.exe',original_file_name=''))['evidence_level'],'domain_only')

    def test_release_integrity(self):
        rows=identity.rows()
        identity.validate_release(rows)
        for broken in (rows[:-1],rows[1:],rows+[rows[0]]):
            with self.assertRaises(ValueError): identity.validate_release(broken)
        altered=copy.deepcopy(rows);altered[0]['tool_name']='Other product'
        with self.assertRaises(ValueError): identity.validate_release(altered)

    def test_full_literal_domain_suffix(self):
        self.assertEqual(sources.domain_root('plus*.site24x7.net.au'),'site24x7.net.au')
        self.assertEqual(sources.domain_root('pdqinstallers.*.r2.cloudflarestorage.com'),'r2.cloudflarestorage.com')
        for bad in ('*.foo.*.example.com','*.foo[1-9].example.com','x*com'):
            with self.assertRaises(ValueError): sources.domain_root(bad)

    def test_sources_and_aggregation_contract(self):
        policy,config=rr.load_policy()
        for platform in ('mde','cortex'):
            text=iq.build(bq.build(policy,config,platform),platform)
            self.assertLess(text.index('IdentityBasis='),text.index('ActivityDecision='))
            self.assertIn('DetectedToolId, SoftwareRole, IdentityBasis',text)
            self.assertIn('identity_noise_conflict',text)
            self.assertIn('customer_whitelist',text)
            if platform=='mde':
                self.assertIn('RemoteHost startswith_cs tostring(_PatternParts[0])',text)
                self.assertIn('profile_data_unavailable',text)
            else:
                self.assertIn('wildcard_match(remote_host, pattern)',text)

    def test_noise_conflict_and_customer_priority(self):
        policy,config=rr.load_policy()
        row=dict(process_name='msedge.exe',original_file_name='AnyDesk.exe',
                 process_path=r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
                 signer='Microsoft Corporation',signature_valid=True)
        result=identity.evaluate(policy,config,row)
        self.assertTrue(result['default_rules'])
        self.assertFalse(result['excluded'])
        self.assertEqual(result['evidence_level'],'evidence_conflict')
        rule={'id':'customer-approved','enabled':True,'target':'activity',
              'conditions':[{'field':'process_name','operator':'equals','value':'msedge.exe'}]}
        config=dict(config,whitelist=[rule])
        self.assertTrue(identity.evaluate(policy,config,row)['excluded'])
        rule['expires_at']='2020-01-01T00:00:00Z'
        self.assertFalse(identity.evaluate(policy,config,row)['excluded'])

    def test_process_inventory_uses_child_identity(self):
        policy,config=rr.load_policy()
        mde=iq.process_query(bq.build(policy,config,'mde'), 'mde')
        self.assertIn('InitiatingProcessSHA1=SHA1',mde)
        self.assertIn('InitiatingProcessVersionInfoOriginalFileName=ProcessVersionInfoOriginalFileName',mde)
        self.assertNotIn('DeviceNetworkEvents',mde)
        self.assertNotIn('mv-expand LabelIndex',mde)
        xql=iq.process_query(bq.build(policy,config,'cortex'), 'cortex')
        self.assertIn('actor_process_signature_vendor=action_process_signature_vendor',xql)
        self.assertIn('actor_process_image_sha256=action_process_image_sha256',xql)
        self.assertIn('ReviewCategory = "process_execution"',xql)
        self.assertNotIn('dataset = lolrmm_domains',xql)
        self.assertIn('ReportSection=',xql)

if __name__=='__main__':unittest.main()
