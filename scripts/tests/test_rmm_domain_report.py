"""Current domain-report contract; fictional customer/context data only."""
import copy
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import rmm_domain_policy as p
import rmm_domain_queries as q
import rmm_domain_report as report
import rmm_report_rules as rr
import rmm_reference_data as ref


def row(**changes):
    return dict(DeviceName='fixture',DeviceId='device-a',Software='Catalog Tool',
        FirstSeen='2026-10-10T01:00:00Z',LastSeen='2026-10-10T01:05:00Z',RemoteHost='relay.example.invalid',
        RemoteIP='192.0.2.1',MatchedDomain='example.invalid',ProcessName='unknown.exe',ProcessPath='C:\\Temp\\unknown.exe',
        User='fictional',SHA1='',SHA256='a'*64,EventCount=3,GeneralRuleIds=[],GeneralWhitelistIds=[],GeneralRelease=p.RELEASE,
        ReportStatus='ok',**changes)


def condition(field,value,op='equals'):return dict(field=field,operator=op,value=value)
def rule(ident,conditions,**kw):return dict(id=ident,enabled=True,target='activity',reason='fixture',conditions=conditions,**kw)
def response(rows):return dict(Results=rows,Schema=[{'Name':f} for f in q.CONTEXT_FIELDS])


class DomainTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.customer=Path(self.tmp.name)/'customer.json'
        self.config=dict(schema_version=1,customer_id='fixture-customer',whitelist=[],retain_rules=[],disabled_default_rules=[])
    def run_report(self,rows):
        self.customer.write_text(json.dumps(self.config),encoding='utf-8')
        return report.finalize_mde_report(response(rows),self.customer,'fixture-customer',dt.datetime(2026,10,10,tzinfo=dt.timezone.utc))
    def test_domain_only_missing_process_hash_is_kept(self):
        data=self.run_report([dict(row(),ProcessName='',ProcessPath='',SHA256='')])['rows']
        self.assertEqual(len(data),1);self.assertEqual(data[0]['MatchedDomains'],['example.invalid'])
        self.assertEqual(list(data[0]),q.REPORT_FIELDS)
    def test_custom_scope_requires_same_context(self):
        self.config['whitelist']=[rule('approved-hash-host',[condition('sha256','a'*64),condition('remote_host','relay.example.invalid')])]
        first=dict(row(),SHA256='b'*64)
        other=dict(row(),RemoteHost='other.example.invalid',LastSeen='2026-10-10T01:10:00Z')
        result=self.run_report([first,other])
        self.assertEqual(result['summary']['contexts_excluded'],0)
        self.assertEqual(result['rows'][0]['SHA256'],'a'*64)
        self.assertEqual(self.run_report([row()])['rows'],[])
    def test_retain_disable_and_explicit_whitelist_priority(self):
        noisy=dict(row(),GeneralRuleIds=['rpt-browser-standard'])
        self.assertEqual(self.run_report([noisy])['rows'],[])
        self.config['retain_rules']=[rule('retain-device',[condition('device_id','device-a')])]
        self.assertEqual(len(self.run_report([noisy])['rows']),1)
        self.config['whitelist']=[rule('approved-device',[condition('device_id','device-a'),condition('sha256','a'*64)])]
        self.assertEqual(self.run_report([noisy])['rows'],[])
        self.config['whitelist']=[];self.config['retain_rules']=[]
        self.config['disabled_default_rules']=['rpt-browser-standard']
        self.assertEqual(len(self.run_report([noisy])['rows']),1)
        self.assertEqual(self.run_report([dict(noisy,GeneralWhitelistIds=['global-approval'])])['rows'],[])
    def test_expired_customer_rule_does_not_hide(self):
        self.config['whitelist']=[rule('expired',[condition('device_id','device-a')],expires_at='2026-10-09T23:59:59Z')]
        self.assertEqual(len(self.run_report([row()])['rows']),1)
    def test_counts_deduplicate_ioc_associations_and_keep_latest_tuple(self):
        earlier=row();duplicate=dict(earlier,MatchedDomain='relay.example.invalid')
        later=dict(row(),ProcessName='renamed.exe',ProcessPath='D:\\Support\\renamed.exe',SHA256='b'*64,User='latest-user',
            RemoteHost='other.example.invalid',RemoteIP='192.0.2.2',LastSeen='2026-10-10T01:10:00Z',EventCount=2)
        data=self.run_report([earlier,duplicate,later])['rows'][0]
        self.assertEqual(data['EventCount'],5)
        self.assertEqual((data['ProcessName'],data['ProcessPath'],data['SHA256'],data['User']),
            ('renamed.exe','D:\\Support\\renamed.exe','b'*64,'latest-user'))
        self.assertEqual(set(data['RemoteHosts']),{'relay.example.invalid','other.example.invalid'})
        self.assertEqual(set(data['MatchedDomains']),{'example.invalid','relay.example.invalid'})
    def test_multi_tool_and_customer_isolation(self):
        self.assertEqual(len(self.run_report([row(),dict(row(),Software='Another Tool')])['rows']),2)
        with self.assertRaises(ValueError):report.finalize_mde_report(response([row()]),self.customer,'other-customer')
    def test_missing_or_failed_or_truncated_results_raise(self):
        self.run_report([])
        for data in [response([{'ReportStatus':'reference_or_policy_unavailable'}]),
                     {'Results':[]},dict(response([]),hasMoreResults=True),{'error':{'code':'failed'}}]:
            with self.assertRaises(ValueError):report.finalize_mde_report(data,self.customer,'fixture-customer')
    def test_current_queries_have_no_identity_gate_or_rule_literals(self):
        policy,config=p.load_policy()
        literal=['chrome.exe','oth.eve.mdt.qq.com','rpt-browser-standard']
        for text in [q.build_mde('1h'),q.build_cortex('1h')]:
            for token in ['FileProfile','DeviceProcessEvents','DeviceFileCertificateInfo','rmm_tool_profiles','rmm_discovery_indicators','IdentityValid','ReportSection']+literal:
                self.assertNotIn(token,text)
        prepared=report.prepare_mde_query(q.build_mde('1h'))
        self.assertEqual(prepared,q.build_mde('1h',contexts=True))
        self.assertIn('GeneralRuleIds',prepared)
        with self.assertRaises(ValueError):report.prepare_mde_query('old query')
    def test_literal_condition_rows_no_quadratic_in_expansion(self):
        records=p.policy_rows();p.validate_rows(records)
        self.assertLess(len(records),250)
        self.assertFalse(any(r['regex_key'] for r in records))
        self.assertTrue(any(r['operator']=='contains' for r in records))
        corrupt=copy.deepcopy(records);corrupt.pop(0)
        with self.assertRaises(ValueError):p.validate_rows(corrupt)
    def test_current_noise_boundaries_do_not_require_certificates(self):
        policy,config=p.load_policy()
        fixtures=[('chrome.exe','C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe','x.example.invalid',True),
            ('chrome.exe','C:\\Temp\\chrome.exe','x.example.invalid',False),
            ('sgwizard.exe','D:\\Apps\\SogouInput\\sgwizard.exe','oth.eve.mdt.qq.com',True),
            ('sgwizard.exe','D:\\Apps\\SogouInputFake\\sgwizard.exe','oth.eve.mdt.qq.com',False),
            ('sgwizard.exe','D:\\Apps\\SogouInput\\sgwizard.exe','other.mdt.qq.com',False),
            ('qq.exe','D:\\QQ\\qq.exe','oth.eve.mdt.qq.com',False),
            ('agent.exe','C:\\Program Files\\ManageEngine\\UEMS_Agent\\agent.exe','x.example.invalid',True),
            ('agent.exe','C:\\Program Files\\ManageEngine\\Other\\agent.exe','x.example.invalid',False)]
        for name,path,host,expected in fixtures:
            actual=rr.evaluate(policy,config,dict(process_name=name,process_path=path,remote_host=host))['excluded']
            self.assertEqual(actual,expected,(name,path,host))
        probe=dict(process_name='freshservice.discoveryprobe.scanservice.exe',process_path='C:\\Probe\\scan.exe',rmm_tool='Freshservice')
        self.assertTrue(rr.evaluate(policy,config,probe)['excluded'])
        self.assertFalse(rr.evaluate(policy,config,dict(probe,rmm_tool='Other RMM'))['excluded'])
        self.assertFalse(rr.evaluate(policy,config,dict(probe,process_name='unknown.exe'))['excluded'])
    def test_unsupported_dynamic_regex_and_signature_are_rejected(self):
        policy,config=p.load_policy()
        config['whitelist']=[rule('signature',[condition('signer','fixture')])]
        with self.assertRaises(ValueError):p.validate_config(policy,config)
        config['whitelist']=[rule('complex-path',[condition('process_path','*support*agent.exe','glob')])]
        with self.assertRaises(ValueError):p.validate_config(policy,config)
    def test_source_patterns_are_validated_before_publish(self):
        p.domain_rows()
        with self.assertRaises(ValueError):p.validate_domains([dict(domain='example.invalid',rmm_tool='fixture',pattern='*.x*.example.invalid')])
    def test_api_timestamp_precision_is_preserved(self):
        data=self.run_report([dict(row(),FirstSeen='2026-10-10T01:00:00.1234567Z',LastSeen='2026-10-10T01:05:00.1234567Z'),
            dict(row(),ProcessName='later.exe',LastSeen='2026-10-10T01:05:00.1234568Z')])['rows'][0]
        self.assertEqual(data['LastSeen'],'2026-10-10T01:05:00.1234568Z')
        self.assertEqual(data['ProcessName'],'later.exe')


if __name__=='__main__':unittest.main()
