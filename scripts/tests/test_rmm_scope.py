"""Boundary checks for report scope and certificate evidence provenance."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import rmm_report_rules as rr
import build_rmm_queries as bq


def cases():
    base = {'device_id': 'fixture-device', 'process_name': 'outlook.exe',
            'process_path': r'C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE',
            'signer': 'Microsoft Corporation', 'signature_valid': True,
            'remote_host': 'oth.eve.mdt.qq.com', 'sha1': 'a' * 40, 'sha256': 'b' * 64}
    rows = []
    def add(name, excluded, **changes):
        rows.append({'case_id': name, 'expected_excluded': excluded, **base, **changes})
    add('outlook-standard', True)
    add('outlook-other-host', False, remote_host='relay.example.invalid')
    add('outlook-lookalike-host', False, remote_host='oth.eve.mdt.qq.com.evil.invalid')
    add('outlook-temp', False, process_path=r'C:\Temp\outlook.exe')
    add('outlook-no-signature', False, signer=None, signature_valid=None)
    add('outlook-invalid', False, signature_valid=False)
    add('outlook-publisher-substring', False, signer='Unknown Microsoft Corporation')
    add('yuanbao', True, process_name='yuanbao.exe', process_path=r'D:\Program Files\Tencent\Yuanbao\yuanbao.exe', signer='Tencent Technology (Shenzhen) Company Limited')
    add('yuanbao-user', True, process_name='yuanbao.exe', process_path=r'C:\Users\fictional\Yuanbao\yuanbao.exe', signer='Tencent Technology (Shenzhen) Company Limited')
    add('yuanbao-temp', False, process_name='yuanbao.exe', process_path=r'C:\Temp\yuanbao.exe', signer='Tencent Technology (Shenzhen) Company Limited')
    add('yuanbao-other-host', False, process_name='yuanbao.exe', process_path=r'D:\Program Files\Tencent\Yuanbao\yuanbao.exe', signer='Tencent Technology (Shenzhen) Company Limited', remote_host='other.mdt.qq.com')
    add('ima-standard', True, process_name='ima.copilot.exe', process_path=r'C:\Users\fictional\AppData\Local\ima.copilot\Application\ima.copilot.exe', signer='Tencent Technology(Shenzhen) Company Limited')
    add('ima-standalone', True, process_name='ima.copilot.exe', process_path=r'D:\ima.copilot\ima.copilot.exe', signer='Tencent Technology (Shenzhen) Company Limited')
    add('ima-lookalike', False, process_name='ima.copilot.exe', process_path=r'D:\ima.copilot.fake\ima.copilot.exe', signer='Tencent Technology (Shenzhen) Company Limited')
    add('ima-invalid', False, process_name='ima.copilot.exe', process_path=r'D:\ima.copilot\ima.copilot.exe', signer='Tencent Technology (Shenzhen) Company Limited', signature_valid=False)
    add('mac-chrome-helper', True, process_name='Google Chrome Helper', process_path='/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/154.0.0/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper', signer='Developer ID Application: Google LLC (EQHXZ8M8AV)')
    add('mac-chrome-lowercase', True, process_name='google chrome helper', process_path='/applications/google chrome.app/contents/frameworks/google chrome framework.framework/versions/154.0.0/helpers/google chrome helper.app/contents/macos/google chrome helper', signer='Developer ID Application: Google LLC (EQHXZ8M8AV)')
    add('mac-chrome-renderer', True, process_name='Google Chrome Helper (Renderer)', process_path='/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/154.0.0/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)', signer='Developer ID Application: Google LLC (EQHXZ8M8AV)')
    add('mac-chrome-main', True, process_name='Google Chrome', process_path='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', signer='Google LLC')
    add('mac-chrome-fake-bundle', False, process_name='Google Chrome', process_path='/Applications/Google Chrome Fake.app/Contents/MacOS/Google Chrome', signer='Google LLC')
    add('mac-chrome-no-signature', False, process_name='Google Chrome', process_path='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', signer=None, signature_valid=None)
    add('mac-edge-helper', True, process_name='Microsoft Edge Helper', process_path='/Applications/Microsoft Edge.app/Contents/Frameworks/Microsoft Edge Framework.framework/Versions/154.0.0/Helpers/Microsoft Edge Helper.app/Contents/MacOS/Microsoft Edge Helper', signer='Developer ID Application: Microsoft Corporation (UBF8T346G9)')
    add('mac-edge-invalid', False, process_name='Microsoft Edge', process_path='/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge', signature_valid=False)
    add('sogou-browser', True, process_name='sogouexplorer.exe', process_path=r'C:\Program Files (x86)\Sogou\SogouExplorer\SogouExplorer.exe', signer='Beijing Sogou Technology Development Co., Ltd.')
    add('sogou-browser-temp', False, process_name='sogouexplorer.exe', process_path=r'C:\Temp\sogouexplorer.exe', signer='Beijing Sogou Technology Development Co., Ltd.')
    for name in ['isgpet.exe', 'sgiguidehelper.exe', 'wbusernetschedule.exe', 'write_spirit.exe', 'sgwizard.exe', 'sogou_voice_assistant.exe', 'sgfeedbackhelper.exe']:
        add('sogou-' + name, True, process_name=name, process_path='D:\\Software\\SogouInput\\Components\\' + name, signer='Beijing Sogou Technology Development Co., Ltd.')
    add('sogou-new-other-host', False, process_name='sgwizard.exe', process_path=r'D:\SogouInput\sgwizard.exe', signer='Beijing Sogou Technology Development Co., Ltd.', remote_host='other.mdt.qq.com')
    add('sogou-new-wrong-path', False, process_name='sgwizard.exe', process_path=r'D:\SogouInputFake\sgwizard.exe', signer='Beijing Sogou Technology Development Co., Ltd.')
    add('meeting-kept', False, process_name='wwmpapp.exe', process_path=r'C:\WxWorkLocal\WeMeet\wwmpapp.exe', signer='Tencent Technology (Shenzhen) Company Limited')
    for name in ['qq.exe', 'tim.exe', 'quickassist.exe', 'remoting_host.exe', 'msedgewebview2.exe', 'anydesk.exe', 'teamviewer_service.exe', 'todesk.exe']:
        add('protected-' + name, False, process_name=name, process_path='C:\\Program Files\\Support\\' + name, signer='Tencent Technology (Shenzhen) Company Limited')
    return rows


class CoverageTest(unittest.TestCase):
    def setUp(self):
        self.policy, self.config = rr.load_policy(rr.ROOT / "rules/legacy/rmm_report_exclusions_v1.json")

    def test_scope_boundaries(self):
        for row in cases():
            with self.subTest(row['case_id']):
                self.assertEqual(rr.evaluate(self.policy, self.config, row)['excluded'], row['expected_excluded'])

    def test_signature_fallback_conflicts_and_provenance(self):
        row = dict(cases()[0], signer=None, signature_valid=None)
        cert = {'DeviceId': 'other-device', 'SHA1': 'a' * 40, 'Timestamp': '2026-10-09T00:00:00Z',
                'IsSigned': True, 'IsTrusted': True, 'Signer': 'Microsoft Corporation'}
        positive = rr.certificate_evidence(row, observations=[cert])
        self.assertIsNone(positive['signature_valid'])
        self.assertIsNone(positive['signer'])
        self.assertEqual(positive['signature_evidence_source'], 'tenant_sha1')
        self.assertTrue(rr.evaluate(self.policy, self.config, positive)['excluded'])
        self.assertFalse(rr.evaluate(self.policy, dict(self.config, mde_hash_signature_fallback=False), positive)['excluded'])
        for change in ({'IsSigned': False}, {'IsTrusted': False}, {'IsTrusted': None},
                       {'Signer': 'Unknown'}, {'Signer': ''}):
            fallback = rr.certificate_evidence(row, observations=[cert, dict(cert, **change)])
            self.assertEqual(fallback['signature_evidence_source'], 'missing')
            self.assertFalse(rr.evaluate(self.policy, self.config, fallback)['excluded'])
        for local in [dict(cert, DeviceId=row['device_id'], IsSigned=False),
                      dict(cert, DeviceId=row['device_id'], IsTrusted=None),
                      dict(cert, DeviceId=row['device_id'], Signer='')]:
            resolved = rr.certificate_evidence(row, local=local, observations=[cert])
            self.assertEqual(resolved['signature_evidence_source'], 'device_sha1')
            self.assertFalse(rr.evaluate(self.policy, self.config, resolved)['excluded'])
        no_hash = rr.certificate_evidence(dict(row, sha1=''), observations=[cert])
        self.assertEqual(no_hash['signature_evidence_source'], 'missing')

    def test_customer_signature_conditions_use_local_evidence(self):
        row = dict(cases()[0], signer=None, signature_valid=None, signature_evidence_source='tenant_sha1',
                   exclusion_signer='Microsoft Corporation', exclusion_signature_valid=True)
        config = copy.deepcopy(self.config)
        config['disabled_default_rules'] = ['rpt-outlook-mdt']
        config['whitelist'] = [{'id': 'local-signed', 'enabled': True, 'target': 'activity', 'reason': 'fixture',
                                'conditions': [{'field': 'signature_valid', 'operator': 'equals', 'value': True}]}]
        self.assertFalse(rr.evaluate(self.policy, config, row)['excluded'])
        config['retain_rules'] = [{'id': 'retain-device', 'enabled': True, 'target': 'activity', 'reason': 'fixture',
                                  'conditions': [{'field': 'device_id', 'operator': 'equals', 'value': row['device_id']}]}]
        config['disabled_default_rules'] = []
        self.assertFalse(rr.evaluate(self.policy, config, row)['excluded'])

    def test_report_category_does_not_suppress_meetings(self):
        row = dict(cases()[0], process_name='wwmpapp.exe', process_path=r'C:\WxWorkLocal\WeMeet\wwmpapp.exe')
        self.assertEqual(rr.review_category(row), 'meeting_component_candidate')
        self.assertFalse(rr.evaluate(self.policy, self.config, row)['excluded'])
        self.assertEqual(rr.review_category(dict(row, process_name=None)), 'process_identity_missing')

    def test_report_views_and_fallback_opt_out(self):
        for platform in ('mde', 'cortex'):
            main = bq.build(self.policy, self.config, platform, view='main')
            review = bq.build(self.policy, self.config, platform, view='review')
            self.assertIn('ReviewCategory != "meeting_component_candidate" and ReviewCategory != "process_identity_missing"', main)
            self.assertIn('"meeting_component_candidate" or ReviewCategory', review)
            with self.assertRaises(ValueError):
                bq.build(self.policy, self.config, platform, mode='audit', view='main')
        disabled = bq.build(self.policy, dict(self.config, mde_hash_signature_fallback=False), 'mde')
        self.assertIn('UseHashEvidence=false and isnull(CertificateObservedAt)', disabled)


if __name__ == '__main__':
    unittest.main()
