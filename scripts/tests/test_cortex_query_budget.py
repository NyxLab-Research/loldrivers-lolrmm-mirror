import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from check_cortex_query_budget import evaluate


class QueryBudgetTests(unittest.TestCase):
    def setUp(self):
        self.quota={'license_quota':1825,'used_quota':2,'daily_used_quota':0.9,'current_concurrent_active_queries_count':0}
        self.policy=dict(daily_limit=5,reserve=4,estimate=0.1,rmm_daily_budget=1,rmm_spent=0.8)

    def test_annual_balance_cannot_override_daily_reserve(self):
        self.assertTrue(evaluate(self.quota,**self.policy)['allowed'])
        self.quota['daily_used_quota']=1.1
        self.assertEqual(evaluate(self.quota,**self.policy)['reason'],'other_projects_reserve')

    def test_shared_usage_and_rmm_usage_are_both_checked(self):
        self.assertEqual(evaluate(self.quota,**dict(self.policy,rmm_spent=1))['reason'],'rmm_budget_insufficient')
        self.quota['current_concurrent_active_queries_count']=1
        self.assertEqual(evaluate(self.quota,**self.policy)['reason'],'another_query_active')

    def test_missing_daily_field_and_invalid_usage_fail_closed(self):
        del self.quota['daily_used_quota']
        self.assertEqual(evaluate(self.quota,**self.policy)['reason'],'quota_fields_unavailable')
        self.quota['daily_used_quota']=float('nan')
        self.assertEqual(evaluate(self.quota,**self.policy)['reason'],'quota_fields_invalid')

    def test_invalid_budget_never_allows_a_query(self):
        for changes in ({'estimate':0},{'reserve':6},{'rmm_daily_budget':2},{'estimate':float('nan')}):
            with self.assertRaises(ValueError):evaluate(self.quota,**dict(self.policy,**changes))


if __name__=='__main__':unittest.main()
