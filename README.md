# LOLDrivers + LOLRMM queries

Public reference data and MDE/Cortex queries. Credentials, customer approvals,
private queries and validation results stay in ignored config/, output/ and tmp/.
LOLDrivers hash queries are independent and unchanged.

## Current domain report

Use queries/mde/lolrmm.kql or queries/cortex/lolrmm.xql. One public RMM query per
platform, default seven days. Validate with **one hour** and the same explicit
API timeframe. Dev owns the existing Excel/email/report executor; this repository
supplies queries, reference maintenance and a private MDE customer-filter adapter.

Domain match -> general noise exclusions -> customer whitelist -> aggregation.
There is no process identity requirement, process-start scan, certificate join,
FileProfile or main/review split. Missing catalog file metadata does not prevent
a domain match. Process fields are supporting endpoint telemetry.

Original exact/one-star patterns remain intact. Suffix buckets narrow candidates;
only the full pattern establishes a match. This is more specific than widening
every literal indicator to all subdomains. Shared GitHub hosting exclusions remain
in .github/lolrmm_domain_exclusions.csv. Websites are not network indicators.

Software is the feed's **associated tool**, not confirmed installation, remote
control, malicious activity or authorization. Shared domains can still produce
false positives; unknown/self-hosted infrastructure and absent network telemetry
remain outside this report. Browser activity is deliberately outside report scope.
ManageEngine exclusions do not deny that product's remote capability.

The 13 columns, in order: DeviceName, Software, LastSeen, FirstSeen, RemoteHosts,
RemoteIPs, MatchedDomains, ProcessName, ProcessPath, User, SHA256, EventCount,
ReportStatus. Each row is one device/tool pair. Path/user/hash belong to **one
latest retained context**. Destinations/domains are independent historical sets.
EventCount counts source network records, deduplicated across indicators for the
same context/tool; it is not a session count. MDE uses ConnectionSuccess; Cortex
uses NETWORK telemetry without asserting all records are successful connections.

Require ReportStatus=ok and complete API results before delivery. Health/control
rows are not devices or empty successful reports. Missing lookups cause API errors;
partial rule releases/unsupported operators emit a health row. Fetch Cortex result
streams and verify totals. Export by schema; Graph OData annotations are metadata.

## General and customer maintenance

| Source | Consumption |
|---|---|
| rules/rmm_report_exclusions.json | Current noise rules -> public data/rmm_general_rules.csv |
| rules/rmm_general_whitelist.json | Explicit general approvals -> the same table; initially empty |
| config/rmm_customers/customer.json | Private customer whitelist, expiry, retain/disable overrides |
| data/lolrmm_domains.csv | LOLRMM network patterns -> MDE externaldata / Cortex lookup |

Default rules use browser names plus browser paths, Sogou input component paths
plus its specific shared telemetry host, ManageEngine component paths and the
previously reviewed Outlook/Yuanbao/ima shared-host noise. Freshservice inventory
components use specific Discovery Agent paths or Probe names plus its tool label;
the vendor's domains remain eligible for other processes. They do not scan
certificates. Missing fields do not satisfy exclusions or approvals.

Rule values/IDs stay **outside query text**. The fixed evaluator supports
equals/exact/in, path_prefix, path contains, domain_suffix and path glob with at
most one star. Conditions AND; alternatives/rules OR. Windows paths are case
insensitive, Unix paths retain case. Domains require exact/boundary-aware suffix,
not substring approvals. Raw regex/complex glob is rejected: MDE requires regex
constants, which would otherwise put rule branches back into queries.

Supported context fields: device_id, device_name, process_name, process_path,
sha256, remote_host, matched_domain, rmm_tool, and MDE-only sha1. rmm_tool uses
the feed label, case insensitive. matched_domain/rmm_tool require association
target. Prefer tool/host plus device/path/hash scope. Current reports reject
signature and old identity tool_id/software_role conditions, not ignore them.
UTC expiry is evaluated at execution. Explicit whitelists win; retain_rules
only override general noise. disabled_default_rules disables chosen noise IDs.
These rules affect report visibility, not EDR enforcement or alerting.

Cortex applies both tables natively. The public MDE query directly shows the
general-filtered report. Customer handling uses the adapter below, retaining
general-excluded contexts until private retain/disable/whitelist evaluation.
Private customer rules never enter public feeds or generated query branches.

```python
from pathlib import Path
from rmm_domain_report import prepare_mde_query, finalize_mde_report

query = prepare_mde_query(Path('queries/mde/lolrmm.kql').read_text())
# Existing executor sets the window and retrieves complete API results.
response = existing_hunting_executor(query)
report = finalize_mde_report(response, Path('config/rmm_customers/example.json'), 'example')
existing_excel_export(report['rows'])
```

The adapter accepts Graph results/schema or Defender Results/Schema, checks
customer_id, rejects health errors/missing schema/apparent truncation and filters
**before aggregation**. Independent path/hash/domain arrays cannot form approvals.
Dev must connect these two functions in its existing executor; that source is not
here. Until then, copying the public MDE query applies general rules only.

## Generation and tests

Python 3.10+; generation/customer filtering use the standard library.

```console
python scripts/rmm_reference_data.py
python scripts/build_rmm_queries.py
python scripts/rmm_reference_data.py --check
python scripts/build_rmm_queries.py --check
python -m unittest discover -s scripts/tests -v
python scripts/build_rmm_queries.py --timeframe 1h --output-dir output/rmm/test
python scripts/build_rmm_queries.py --platform mde --contexts --timeframe 1h --output-dir output/rmm/dev
```

Default writes only two public query files. --customer validates private rules;
MDE emits contexts and Cortex reads its private lookup. Customer/context/test
outputs remain under output/ or tmp/. Start from rules/rmm_customer.example.json;
rules/rmm_customer.whitelist.example.json demonstrates a fictional scoped approval.
Historical identity code/data and rules/legacy remain for regression/rollback,
and are not used by the current default query or Cortex updater.

## Cortex deployment

```console
python -m pip install -r requirements-rmm.txt
python scripts/sync_rmm_references.py --published
python scripts/sync_rmm_references.py --published --apply
```

Private centralized config/cortex_credentials.yml drives synchronization. MDE
keys are never needed on that server. --tenant selects aliases, --customer-dir
selects private policies, --state-dir stores inventories/backups/receipts.
New aliases are inventoried on subsequent runs. customer_id must match the alias.

The updater inventories and backs up before mutation. It maintains only
lolrmm_domains, rmm_general_rules and rmm_customer_rules. Historical identity and
unrelated lookups remain intact. --published pins one GitHub commit and verifies
domain hash/count/pattern grammar, rule schema and recomputed digest. Rule rows
are staged/read back, and the manifest is written **last**. Re-runs verify;
three complete releases remain for rollback. Domain deletions over 25% are blocked.

General releases are immutable: increment RELEASE in scripts/rmm_domain_policy.py,
regenerate and publish the CSV for general changes. No query branches or manual
per-tenant imports are needed. Customer revisions advance from remote state.
Shared API hosts sync once; different customer approvals remain blocked until
customer/device isolation is known. Empty shared policies are allowed.

The existing daily server job updates references, not weekly reports. For rule
rollback stop the updater and remove only the newest manifest by row_id; align
query/data grammar. Do not delete entire lookups. Domain writes have private
backups/readback, but are not atomic; avoid concurrent reports during maintenance.

## Performance and quota

MDE scans successful network connections only. A token prefilter comes from the
complete feed, with broad fallback when safe coverage is unavailable; there is
no process-name prefilter. Small-table bucket lookup and full pattern checks
precede wide aggregation. Cortex selects fields early, filters buckets, aggregates
contexts and checks full patterns after equality joins. Rule anchors avoid an
event/all-rule cross product; duplicate indicators do not inflate counts.

Measure CPU, memory and actual query_cost_charged with a fixed one-hour window
and complete results. Short tests do not certify weekly memory capacity or CU;
time slicing does not guarantee lower CU.

```console
python scripts/check_cortex_query_budget.py --tenant example --daily-limit 5 --reserve 4 --estimate 0.2 --rmm-daily-budget 1 --rmm-spent 0
```

Use confirmed tenant daily limits and conservative measured estimates. Annual
license_quota/used_quota are not daily remaining quota. The read-only admission
helper defers on missing data, active queries or insufficient reserve. It does
not provide a server cost cap or reserve against other projects. Dev must call
it before submission and record actual RMM CU; portal queries bypass this check.

## Official references

- [LOLRMM detections](https://lolrmm.io/detections/) and [feeds](https://lolrmm.io/api/).
- [MDE network schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table), [performance](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices) and [limits](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-errors).
- [Kusto lookup](https://learn.microsoft.com/en-us/kusto/query/lookup-operator?view=microsoft-fabric) and [regex](https://learn.microsoft.com/en-us/kusto/query/matches-regex-operator?view=microsoft-fabric).
- [Cortex Start XQL](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Start-an-XQL-Query), [Get results](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-XQL-Query-Results) and [lookup writes](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Add-or-update-data-in-a-lookup-dataset).
- [Cortex quota](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-XQL-Query-Quota), [daily CU](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-5.x-Documentation/Compute-units-usage) and [JSON types](https://docs-cortex.paloaltonetworks.com/r/Cortex/Cortex-XQL-Command-Reference/Core-Concept-Why-XQL-has-four-JSON-extraction-functions).
- [Freshservice Discovery Agent architecture and installation paths](https://support.freshservice.com/support/solutions/articles/50000009811-discovery-agent-architecture-and-working).
