# LOLDrivers + LOLRMM queries

Public reference data, General/Custom report rules and MDE/Cortex queries.
Credentials, private queries and validation results stay in ignored config/, output/ and tmp/.
LOLDrivers hash queries are independent and unchanged.

## Current domain report

Use queries/mde/lolrmm.kql or queries/cortex/lolrmm.xql. One public RMM query per
platform, default seven days. Validate with **one hour** and the same explicit
API timeframe. Dev owns the existing Excel/email/report executor; this repository
supplies queries and reference maintenance. No repository Python function is
required in Dev's MDE report executor.

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
| [rules/rmm_general_rules.json](rules/rmm_general_rules.json) | General noise rules and global whitelist -> public data/rmm_general_rules.csv |
| [rules/rmm_customer_rules.json](rules/rmm_customer_rules.json) | One master for all customers, keyed by customer code -> public data/rmm_customer_rules.csv |
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

Edit only the two linked JSON source files. On a main-branch change, **Publish RMM
rule feeds** validates the sources, advances changed release numbers and commits
the generated CSV feeds. Wait for that workflow to succeed before expecting a
rule change to apply. MDE reads the published feeds at query time; Cortex receives
them through the daily reference sync. Neither rule values nor customer-specific
branches are copied into query text. Source-only commits keep the previous CSV
active until successful publication; a failed build does not publish new rules.

Customer codes and rule conditions in this master are public, as are General
rules. Keep API keys, tokens and any future sensitive rule values out of it.
All 39 registered customers initially have empty Custom rules. For a new customer,
add an entry with empty whitelist/retain_rules/disabled_default_rules arrays;
register its credentials privately only if API access is needed.

Both queries apply General and Custom natively, before aggregation. In MDE, set
the registered customer code near the top of the query, for example:

```kusto
let CustomerId="fung";
```

Dev substitutes this quoted value in its existing script along with the report
time window, calls its existing hunting API and exports the returned rows. Validate
the code against the master and allow only lowercase letters, digits, hyphens and
underscores when substituting. The default `set-customer-id`, a typo or a missing
customer manifest returns a health error, not a General-only report. An explicitly
registered empty customer is valid. Cortex needs no customer parameter: each
physical tenant's `rmm_customer_rules` lookup contains only its own subset.

Example entry inside the master `customers` object (fictional; not an active rule):

```json
"example": {
  "disabled_default_rules": [],
  "retain_rules": [],
  "whitelist": [{
    "id": "example-approved-support", "reason": "Approved support on one device",
    "enabled": true, "target": "association", "expires_at": "2027-01-01T00:00:00Z",
    "conditions": [
      {"field": "device_id", "operator": "equals", "value": "example-device-id"},
      {"field": "rmm_tool", "operator": "equals", "value": "TeamViewer"}
    ]
  }]
}
```

Current Cortex RMM queries need only `lolrmm_domains`, `rmm_general_rules` and
`rmm_customer_rules`. The retired `rmm_tool_profiles`, `rmm_tool_profiles_v2`
and `rmm_discovery_indicators` lookups are no longer synchronized by the scheduled
jobs. Before removing old lookups, back up their data and check tenant dependencies.
Keep `loldrivers_hashes` for the independent LOLDrivers query.

The previous per-customer config files and `rmm_domain_report` Python adapter are
legacy compatibility tools. The current public queries and scheduled Cortex job
do not consume those private customer files. Do not maintain rules in both places.

## Generation and tests

Python 3.10+; generation/customer filtering use the standard library.

```console
python scripts/refresh_rmm_rules.py
python scripts/build_rmm_queries.py
python scripts/rmm_reference_data.py --check
python scripts/build_rmm_queries.py --check
python -m unittest discover -s scripts/tests -v
python scripts/build_rmm_queries.py --timeframe 1h --output-dir output/rmm/test
python scripts/build_rmm_queries.py --platform mde --customer-id fung --timeframe 1h --output-dir output/rmm/dev
```

Default writes only two public query files. --customer-id validates a registered
code and fills the MDE parameter. --contexts is for internal debugging only.
Customer/context/test outputs remain under output/ or tmp/.
Historical identity code/data and rules/legacy remain for regression/rollback,
and are not used by the current default query or Cortex updater.

## Cortex deployment

```console
python -m pip install -r requirements-rmm.txt
python scripts/sync_rmm_references.py --published
python scripts/sync_rmm_references.py --published --apply
```

Private centralized config/cortex_credentials.yml drives synchronization. MDE
keys are never needed on that server. --tenant selects aliases; --state-dir stores
inventories/backups/receipts. --published reads the same public Custom master feed
as MDE, pinned to the same commit as General/domains. Local development can use
--customer-file to select an alternative JSON master.
New aliases must be registered in the master before synchronization.

Current provisioned Cortex scope: **k11-hk, newworld, nwcl, cpy, shunhing, jec,
glshk, nws, esf** (nine physical tenants). ESF's three credential aliases share
one API host and are inventoried/synchronized once. Do not add an unprovisioned
Cortex customer to report scheduling merely because it is registered for MDE.

The updater inventories and backs up before mutation. It maintains only
lolrmm_domains, rmm_general_rules and rmm_customer_rules. Historical identity and
unrelated lookups remain intact. --published pins one GitHub commit and verifies
domain hash/count/pattern grammar, rule schema and recomputed digest. Rule rows
are staged/read back, and the manifest is written **last**. Re-runs verify;
three complete releases remain for rollback. Domain deletions over 25% are blocked.

General releases are immutable: the publication workflow advances the release
when compiled content changes. Customer master releases are also automatic;
tenant-local Customer revisions advance from remote state only when that tenant's
subset changes. No query branches or manual per-tenant imports are needed.
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
