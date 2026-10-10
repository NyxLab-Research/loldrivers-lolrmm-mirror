"""Read-only Cortex admission check. It never starts a query or changes tenant limits."""
import argparse
import json
import math
from cortex_lookup import CortexClient, SyncError
from tenant_credentials import cortex_tenants


def amount(value,name):
    if isinstance(value,bool):raise ValueError(name+' must be a non-negative number')
    result=float(value)
    if not math.isfinite(result) or result<0:raise ValueError(name+' must be a non-negative number')
    return result


def evaluate(quota,*,daily_limit,reserve,estimate,rmm_daily_budget,rmm_spent):
    """Estimate-based admission, not a server-enforced cost cap or reservation."""
    limits={key:amount(value,key) for key,value in locals().copy().items() if key!='quota'}
    daily_limit,reserve,estimate,rmm_daily_budget,rmm_spent=(limits[k] for k in ('daily_limit','reserve','estimate','rmm_daily_budget','rmm_spent'))
    if estimate<=0 or daily_limit<=0 or reserve>daily_limit or rmm_daily_budget>daily_limit-reserve:
        raise ValueError('Use a positive cost estimate and a budget that preserves the reserve')
    required=('license_quota','used_quota','daily_used_quota','current_concurrent_active_queries_count')
    if any(k not in quota or quota[k] is None for k in required):
        return {'allowed':False,'reason':'quota_fields_unavailable'}
    try:
        annual=sum(amount(quota.get(k,0),k) for k in ('license_quota','additional_purchased_quota','eval_quota'))
        annual_remaining=max(0,annual-amount(quota['used_quota'],'used_quota'))
        daily_remaining=max(0,daily_limit-amount(quota['daily_used_quota'],'daily_used_quota'))
        active=amount(quota['current_concurrent_active_queries_count'],'active_queries')
    except (TypeError,ValueError):
        return {'allowed':False,'reason':'quota_fields_invalid'}
    reason='allowed'
    def exceeds(available):
        return estimate>available and not math.isclose(estimate,available,rel_tol=0,abs_tol=1e-12)
    if active>0:reason='another_query_active'
    elif exceeds(rmm_daily_budget-rmm_spent):reason='rmm_budget_insufficient'
    elif exceeds(annual_remaining):reason='annual_quota_insufficient'
    elif exceeds(daily_remaining-reserve):reason='other_projects_reserve'
    return {'allowed':reason=='allowed','reason':reason,'daily_remaining_cu':daily_remaining,
            'annual_remaining_cu':annual_remaining,'reserve_cu':reserve,'estimated_query_cu':estimate}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tenant',required=True)
    for option in ('daily-limit','reserve','estimate','rmm-daily-budget','rmm-spent'):
        parser.add_argument('--'+option,type=float,required=True)
    args=parser.parse_args()
    tenants=cortex_tenants(selected=[args.tenant])
    if len(tenants)!=1:raise ValueError('Select one configured Cortex tenant')
    result=evaluate(CortexClient(tenants[0],40).get_query_quota(),daily_limit=args.daily_limit,
                    reserve=args.reserve,estimate=args.estimate,rmm_daily_budget=args.rmm_daily_budget,rmm_spent=args.rmm_spent)
    print(json.dumps({'tenant':args.tenant,**result}))
    return 0 if result['allowed'] else 2


if __name__=='__main__':
    try:raise SystemExit(main())
    except (SyncError,ValueError) as exc:
        print(json.dumps({'allowed':False,'reason':'check_failed','error':str(exc)}))
        raise SystemExit(2)
