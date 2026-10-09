import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import rmm_identity as identity
import sync_rmm_profiles as sync

class Fake:
    def __init__(self): self.data=[]; self.calls=[]; self.corrupt=False
    def get_dataset_names(self): return {sync.SPEC.name}
    def get_rows(self,name): return list(self.data)
    def add_rows(self,spec,rows):
        self.calls.append(rows)
        self.data.extend(rows[:-1] if self.corrupt else rows)

class Immediate:
    def run(self,fn): return fn()

class ReleaseTests(unittest.TestCase):
    def test_stage_activate_idempotent(self):
        c=Fake(); desired=identity.rows()
        self.assertEqual(sync.sync(c,desired)['status'],'planned');self.assertEqual(c.data,[])
        self.assertEqual(sync.sync(c,desired,apply=True,limiter=Immediate())['status'],'activated')
        self.assertEqual(len(c.calls),2)
        self.assertTrue(all(r['record_type']=='profile' for r in c.calls[0]))
        self.assertEqual(c.calls[-1][0]['record_type'],'manifest')
        sync.sync(c,desired,apply=True,limiter=Immediate());self.assertEqual(len(c.calls),2)
    def test_bad_stage_never_activates(self):
        c=Fake();c.corrupt=True
        with self.assertRaises(ValueError):sync.sync(c,identity.rows(),apply=True,limiter=Immediate())
        self.assertFalse(any(r['record_type']=='manifest' for r in c.data))
    def test_changed_release_rejected(self):
        c=Fake();c.data=identity.rows();c.data[0]=dict(c.data[0],tool_name='changed')
        with self.assertRaises(ValueError):sync.sync(c,identity.rows(),apply=True,limiter=Immediate())
        self.assertEqual(c.calls,[])

if __name__=='__main__': unittest.main()
