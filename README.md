# LOLDrivers + LOLRMM queries

Public reference data and native MDE/Cortex queries. Credentials, customer rules,
private queries and validation results stay in ignored config/, output/ and tmp/.

## Customer RMM query

Use **queries/mde/lolrmm.kql** or **queries/cortex/lolrmm.xql**. Each platform has
one public RMM entry point. Defaults are seven days and **main only**. Validate
with **one hour** and a matching explicit API timeframe. Dev executes the native
query and uses its existing report/export system; this repository does not send
reports or require dev to reimplement identity/whitelist matching.

Discovery uses **domain OR process**. Successful MDE connections retain the
domain entry independently of executable/signature coverage; process discovery
also covers IP/self-hosted infrastructure. Main requires either a reviewed,
validly signed process identity, or a specific catalog process and domain
matching **the same tool and source context**. Missing/invalid signatures do not
automatically discard corroborated RMM; SignatureStatus shows their evidence.
MDE rejects contradictory file metadata, and both platforms enforce reviewed
path constraints. Cortex NETWORK records and child process starts are
separate activity types; STORY records are not counted as network activity.
Cortex leaves process-start User empty when only initiating-user evidence exists.

Reviewed signer profiles cover 14 families and 41 aliases. Candidate discovery
additionally consumes the broader catalog, including bounded AnyDesk custom-name
patterns. Generic executable names cannot establish process evidence; colliding
catalog names stay in review. Domain-only and uncorroborated process candidates,
QQ/TIM and management agents stay in review. Freshservice discovery components
are explicitly management scope. Main remains an evidence-based subset, not a
complete inventory or proof of a remote session, malicious activity or approval.

The 16 customer columns, in order, are DeviceName, Software, LastSeen, FirstSeen,
RemoteHosts, RemoteIPs, MatchedDomains, Evidence, ProcessName, ProcessPath, User,
Publisher, SignatureStatus, SHA256, Activities, ReportStatus. Each main row
summarizes one device/software pair. Process, hash, publisher, user and signature
come from **one coherent latest source record**. Destinations, matched domains
and evidence are independent sets across retained contexts; a later process
start cannot erase an earlier destination. Empty sets mean no observed value.
FirstSeen/LastSeen cover retained events. Activities separates network activity,
process starts and recognized-process connection attempts; attempts alone do
not satisfy domain corroboration.
Use the private details view for distinct file/context records and forensic SHA1.

MDE uses the latest certificate observation for the same device/SHA1 **inside
the report window**. When no local record exists, bounded FileProfile(SHA1,1000)
enrichment requires Available, SignedValid, a valid certificate and the expected
signer. A local negative/incomplete record always takes precedence. File evidence
does not prove the current endpoint's trust state. Missing evidence stays in
review unless process/domain corroboration independently qualifies; overflow or
service errors emit an incomplete status. FileProfile is limited to aliases
needing reviewed identity or narrow noise checks. A private customer
can set mde_file_profile_fallback to false. The older mde_hash_signature_fallback
option belongs to the legacy domain audit.

**Require ReportStatus=ok before customer delivery.** Error rows are control
records, not devices. Missing Cortex datasets cause explicit query errors;
partial references or unknown regex keys cause health rows. API failures,
truncation and enrichment failures must not become empty successful reports.
Fetch Cortex result streams when necessary and verify returned versus total rows.
Export by schema; Graph OData type annotations are metadata, not report columns.

Performance changes preserve these discovery and evidence standards. MDE matches
indicators before aggregating source events, avoids a broad source cache, and
uses lookup for the small right-hand policy table. Cortex selects raw fields
early and uses domain suffix buckets for equality joins, followed by the full
original domain-boundary and pattern checks. A bucket never establishes a match.
Main prunes contexts only once they cannot qualify; all/review retain independent
domain candidates. FileProfile remains bounded to evidence needed by that view.
Lookup schemas/releases and the 16-column export contract do not change.
Benchmark with a fixed one-hour window, complete results and the same reference
versions. Record actual Cortex query_cost_charged separately from API/poll latency;
one-hour success does not establish weekly memory capacity or weekly CU usage.

## Rules and whitelist maintenance

| Input | Purpose | Native consumption |
|---|---|---|
| rules/rmm_identity_profiles.json | Reviewed aliases, signers and roles | Identity CSV / lookup |
| rules/rmm_identity_constraints.json | Per-alias signer/path/display constraints | Same identity table |
| data/rmm_discovery_source.json | Snapshot of catalog process artifacts; no signer trust | Discovery CSV / lookup |
| rules/rmm_catalog_scope.json | Reviewed software scope exceptions, such as inventory agents | Same discovery table |
| rules/rmm_report_exclusions.json | Existing narrow noise exclusions | General condition CSV / lookup |
| rules/rmm_general_whitelist.json | Explicit general report whitelist, initially empty | Same general table |
| config/rmm_customers/customer.json | Private customer approvals, expiry, retain/disable overrides | MDE datatable / tenant-private Cortex lookup |

Ordinary rules use a fixed native evaluator for equality/in, directory prefix
and host suffix. Conditions are ANDed; alternatives, in values and separate rules
are ORed. Simple rules/values are data, without per-rule query branches.
KQL requires constant regex patterns: regex/glob rules use a small compiled
registry. **A new regex pattern requires query regeneration**; ordinary value
changes do not. Unknown keys fail visibly.

Existing general rules retain path, signer and host constraints for browsers,
Sogou input, Outlook/Yuanbao/ima and Endpoint Central. Endpoint Central is a report
scope exclusion, not a claim that it lacks remote-control capability. Shared
vendors/domains are never globally declared safe. Positive identity screening
keeps domain-only browser/Sogou noise out of main; explicit rules remain active
on individual source contexts before aggregation.

For new customer rules prefer canonical **tool_id + device/path/hash scope**,
with target=activity. Native main/review rejects legacy IOC-label rmm_tool or
matched_domain approvals with a migration error; use remote_host for actual-host
restrictions. SHA1 conditions require MDE-only generation; Cortex uses SHA256.
Missing fields never satisfy an approval. Expiry is evaluated at execution in UTC.
The private customer_id must match its Cortex tenant alias before deployment.
retain_rules overrides a common exclusion but cannot create corroboration or
promote management/dual-use software into main. Explicit whitelist rules take
precedence. disabled_default_rules disables selected general noise rules.
All of these affect **report visibility**, not EDR policies or alerts.

## Generate queries

Python 3.10+; query generation itself needs no third-party packages.

```console
python scripts/rmm_reference_data.py
python scripts/rmm_discovery.py
python scripts/build_rmm_queries.py
python scripts/rmm_reference_data.py --check
python scripts/rmm_discovery.py --check
python scripts/build_rmm_queries.py --check
python -m unittest discover -s scripts/tests -v
```

Default generation writes only two public main queries. Customer/internal queries
must stay private; copy rules/rmm_customer.example.json before adding approvals.

```console
python scripts/build_rmm_queries.py --customer config/rmm_customers/example.json --output-dir output/rmm/example
python scripts/build_rmm_queries.py --view all --timeframe 1h --output-dir output/rmm/internal
python scripts/build_rmm_queries.py --view review --timeframe 1h --output-dir output/rmm/review
python scripts/build_rmm_queries.py --view details --timeframe 1h --output-dir output/rmm/details
python scripts/build_rmm_queries.py --view domain-review --timeframe 1h --output-dir output/rmm/domain-audit
```

all includes profile candidates/whitelists, with main before review. review omits
explicit whitelists. details is main file evidence. domain-review preserves the
older broad IOC discovery as an **internal audit source** with general noise
decisions; it is not a native customer-policy view and rejects customer configs.
It preserves exact/wildcard pattern boundaries and unknown-software leads.

MDE embeds customer rules in a generated private typed datatable. Cortex reads
its private customer lookup; generate a customer query when its regex registry
changes. Dev only sets the window, executes the native query and handles delivery.

For MDE main/details, network names are filtered before URL parsing and domain
expansion. Original filename aliases and bounded process prefixes remain eligible.
If an active identity profile lacks a same-tool process indicator, the query falls
back to broad discovery. Internal all/review retain independent domain discovery.
Cortex exact/one-star matching uses split/arrayindex/len for tenant compatibility.
Domain arrays use json_extract_array followed by scalar decoding; some tenants
reject wildcard_match or json_extract_scalar_array even when other tenants accept
the same query. Historical domains and coherent latest process fields are retained.

Query output size and peak memory are not CPU/CU budgets. Before API execution,
dev must check shared tenant usage, maintain a separate RMM cost ledger and reserve
quota for other projects. The read-only helper is an estimate-based admission
check; it does not execute queries or enforce a per-query server cost cap:

```console
python scripts/check_cortex_query_budget.py --tenant example --daily-limit 5 --reserve 4 --estimate 0.2 --rmm-daily-budget 1 --rmm-spent 0
```

Use the tenant's confirmed daily limit and a conservative historical cost estimate
for the same query/window. license_quota/used_quota may be annual values;
daily_used_quota is separate. Missing quota data, another active query or an
insufficient budget defers execution; it must not produce an empty successful
report. A local per-tenant lock prevents overlapping RMM admission checks but
cannot reserve quota against unrelated applications. UI queries bypass this
helper. Never infer a 7-day cost from a 1-hour test or treat time-slicing as a
guaranteed CU reduction. The report executor must explicitly call the helper;
the existing reference-sync schedule does not execute weekly reports.

## Cortex deployment and updates

```console
python -m pip install -r requirements-rmm.txt
python scripts/sync_rmm_references.py --published
python scripts/sync_rmm_references.py --published --apply
```

Private config/cortex_credentials.yml maps aliases to api_url, api_key_id,
api_key and optional auth_method (advanced or standard). enabled=false disables
an entry. config/mde_credentials.yml remains private; Cortex synchronization
never requires MDE keys. Use --tenant for a subset and --customer-dir for a
private rule directory. Never commit credentials or customer-generated queries.

The synchronizer inventories datasets, rejects non-lookup collisions, backs up
relevant rows privately and provisions rmm_tool_profiles_v2,
rmm_discovery_indicators, rmm_general_rules,
rmm_customer_rules and lolrmm_domains. No customer approvals means an empty,
complete customer release. Legacy identity/unrelated lookups remain intact.
Rows are staged, read back with a recomputed content digest and activated by
appending the manifest **last**. Re-runs verify rather than append. Three complete
releases remain for rollback. Domain deletions over 25% are blocked.

General/profile releases are immutable: increment RELEASE in
scripts/rmm_reference_data.py, regenerate and publish reference CSVs for changes.
Customer revisions advance automatically from the remote active release.
Discovery revisions advance automatically when normalized catalog/domain/scope
content changes. Daily refresh grants no new signer trust. Lookup reads accept
bounded gzip responses and retry transient read failures; mutations are not
blindly retried after an unknown outcome.
--published pins downloads to one GitHub commit and verifies schemas, reference
digests, domain hash and counts before writing. An existing server job can run
this daily without manual CSV imports. New YAML entries are inventoried and
provisioned on the next successful run. Tenant failures return a nonzero status.

Repeated API hosts are synchronized once. **Independent customer approvals are
blocked for such aliases until customer/device scope is resolved**. Shared
empty/default policies do not authorize guessed customer exclusions.
For rollback, stop the updater and remove only the newest release's manifest by
row_id, leaving its prior complete release. Revert logic/schema together when
necessary; do not delete an entire lookup to roll back.

## LOLRMM feeds and limits

rmm_tools.json supplies candidate process artifacts plus separate reviewed
executable/publisher proposals. Daily
upstream refresh never automatically approves signers or whitelists.
rmm_domains.csv is an independent discovery entry in the native query. The tools CSV is a tabular
export of the catalog, not independent corroboration. Sigma process/DNS feeds
cross-check aliases/patterns. The count feed checks freshness/coverage.

rmm_certificates.json supports application-control research. Source-file hashes,
certificate thumbprints, Authenticode hashes and page hashes are **not**
interchangeable endpoint SHA256/SignerHash values; this feed is not a direct
identity gate. Unlisted tools, renamed Cortex executables, missing telemetry
and unobserved long-running services can remain outside main. Preserve internal
review/domain discovery to assess coverage.

## Official references

- [LOLRMM feeds](https://lolrmm.io/api/) and [detections](https://lolrmm.io/detections/).
- [MDE network](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table), [process](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table), [certificates](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefilecertificateinfo-table) and [FileProfile](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-fileprofile-function).
- [Graph hunting](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0) and [API migration](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0). Graph needs ThreatHunting.Read.All; legacy-only apps must migrate before their APIs stop returning data on February 1, 2027.
- [KQL externaldata](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator), [lookup](https://learn.microsoft.com/en-us/kusto/query/lookup-operator), [has_any](https://learn.microsoft.com/en-us/kusto/query/has-any-operator), [arg_max](https://learn.microsoft.com/en-us/kusto/query/arg-max-aggregation-function) and [regex](https://learn.microsoft.com/en-us/kusto/query/regex).
- [Cortex Actor](https://docs-cortex.paloaltonetworks.com/r/Cortex-XQL-Schema-Reference-Guide/Actor-Actor), [XQL reference](https://docs-cortex.paloaltonetworks.com/r/Cortex/Cortex-XQL-Command-Reference/Cortex-XQL-Command-Reference) and [first_value](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-3.x-Documentation/first_value).
- [Cortex start](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Start-an-XQL-Query), [results](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-XQL-Query-Results) and [lookup writes](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Add-or-update-data-in-a-lookup-dataset).
- [Cortex filter / IN](https://docs-cortex.paloaltonetworks.com/r/Cortex/Cortex-XQL-Command-Reference/filter), [wildcard_match](https://docs-cortex.paloaltonetworks.com/r/Cortex/Cortex-XQL-Command-Reference/wildcard_match), [JSON scalar arrays](https://docs-cortex.paloaltonetworks.com/r/Cortex/Cortex-XQL-Command-Reference/json_extract_scalar_array) and [lookup reads](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-data-from-a-lookup-dataset).
- [Defender performance](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices), [lookup](https://learn.microsoft.com/en-us/kusto/query/lookup-operator?view=microsoft-fabric), [broadcast join](https://learn.microsoft.com/en-us/kusto/query/broadcast-join?view=microsoft-fabric) and [materialize](https://learn.microsoft.com/en-us/kusto/query/materialize-function?view=microsoft-fabric).
- [Defender CPU limits and errors](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-errors), [Cortex quota API](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-XQL-Query-Quota) and [Cortex daily CU limits](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-5.x-Documentation/Compute-units-usage).
- [Cortex JSON extraction types](https://docs-cortex.paloaltonetworks.com/r/Cortex/Cortex-XQL-Command-Reference/Core-Concept-Why-XQL-has-four-JSON-extraction-functions).
- [Palo Alto XQL performance](https://live.paloaltonetworks.com/t5/cortex-xdr-articles/xdr-best-practices-5-tips-for-better-xql-queries/tac-p/575262) and [XQL APIs / actual query costs](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Running-XQL-Query-APIs).
- [Freshservice discovery scope](https://support.freshservice.com/support/solutions/articles/50000009811-discovery-agent-architecture-and-working).

LOLDrivers CSVs and their independent hash queries remain under data/ and
queries/platform/loldrivers.*.
