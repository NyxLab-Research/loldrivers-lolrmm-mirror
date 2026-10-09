# LOLDrivers + LOLRMM queries

Public reference data and native MDE/Cortex queries. Credentials, customer rules,
private queries and validation results stay in ignored config/, output/ and tmp/.

## Customer RMM query

Use **queries/mde/lolrmm.kql** or **queries/cortex/lolrmm.xql**. Each platform has
one public RMM entry point. Defaults are seven days and **main only**. Validate
with **one hour** and a matching explicit API timeframe. Dev executes the native
query and uses its existing report/export system; this repository does not send
reports or require dev to reimplement identity/whitelist matching.

Main requires a curated specific executable alias, a matching publisher and
valid signing evidence. Selected tools require a dedicated installation path.
MDE also checks OriginalFileName and rejects conflicts. Cortex checks the observed
basename. Known domains are **not a hard gate**, so RMM using IP/self-hosted
infrastructure can qualify. Cortex NETWORK records and child process starts are
separate activity types; STORY records are not counted as network activity.
Cortex leaves process-start User empty when only initiating-user evidence exists.

Initial approved data covers 14 families and 41 aliases, including management
and dual-use candidates for internal review. Invalid/missing signatures,
unsigned RustDesk, QQ/TIM and management agents do not qualify for main. This is
a high-confidence subset, not a complete inventory or proof of a remote session,
malicious activity or customer approval.

The 12 customer columns, in order, are DeviceName, Software, LastSeen, FirstSeen,
Activities, User, ProcessName, ProcessPath, Publisher, SHA256, RemoteHost,
ReportStatus. Each main row summarizes one device/software pair. Process, hash,
publisher, user and remote host come from **one coherent latest source record**,
not exhaustive lists of every binary/destination. FirstSeen/LastSeen cover the
retained events. Activities distinguishes network activity and process starts.
Use the private details view for distinct file/context records and forensic SHA1.

MDE uses the latest certificate observation for the same device/SHA1 **inside
the report window**. When no local record exists, bounded FileProfile(SHA1,1000)
enrichment requires Available, SignedValid, a valid certificate and the expected
signer. A local negative/incomplete record always takes precedence. File evidence
does not prove the current endpoint's trust state. Missing evidence stays in
review; overflow/service errors emit an incomplete status. A private customer
can set mde_file_profile_fallback to false. The older mde_hash_signature_fallback
option belongs to the legacy domain audit.

**Require ReportStatus=ok before customer delivery.** Error rows are control
records, not devices. Missing Cortex datasets cause explicit query errors;
partial references or unknown regex keys cause health rows. API failures,
truncation and enrichment failures must not become empty successful reports.
Fetch Cortex result streams when necessary and verify returned versus total rows.
Export by schema; Graph OData type annotations are metadata, not report columns.

## Rules and whitelist maintenance

| Input | Purpose | Native consumption |
|---|---|---|
| rules/rmm_identity_profiles.json | Reviewed aliases, signers and roles | Identity CSV / lookup |
| rules/rmm_identity_constraints.json | Per-alias signer/path/display constraints | Same identity table |
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
removes domain-only browser/Sogou noise from main before these rules run.

For new customer rules prefer canonical **tool_id + device/path/hash scope**,
with target=activity. Native main/review rejects legacy IOC-label rmm_tool or
matched_domain approvals with a migration error; use remote_host for actual-host
restrictions. SHA1 conditions require MDE-only generation; Cortex uses SHA256.
Missing fields never satisfy an approval. Expiry is evaluated at execution in UTC.
The private customer_id must match its Cortex tenant alias before deployment.
retain_rules overrides a common exclusion but cannot create an identity or
promote management/dual-use software into main. Explicit whitelist rules take
precedence. disabled_default_rules disables selected general noise rules.
All of these affect **report visibility**, not EDR policies or alerts.

## Generate queries

Python 3.10+; query generation itself needs no third-party packages.

```console
python scripts/rmm_reference_data.py
python scripts/build_rmm_queries.py
python scripts/rmm_reference_data.py --check
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
relevant rows privately and provisions rmm_tool_profiles_v2, rmm_general_rules,
rmm_customer_rules and lolrmm_domains. No customer approvals means an empty,
complete customer release. Legacy identity/unrelated lookups remain intact.
Rows are staged, read back with a recomputed content digest and activated by
appending the manifest **last**. Re-runs verify rather than append. Three complete
releases remain for rollback. Domain deletions over 25% are blocked.

General/profile releases are immutable: increment RELEASE in
scripts/rmm_reference_data.py, regenerate and publish reference CSVs for changes.
Customer revisions advance automatically from the remote active release.
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

rmm_tools.json supplies reviewed executable/publisher/artifact proposals. Daily
upstream refresh never automatically approves signers or whitelists.
rmm_domains.csv supports broad internal discovery. The tools CSV is a tabular
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
- [KQL externaldata](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator), [arg_max](https://learn.microsoft.com/en-us/kusto/query/arg-max-aggregation-function) and [regex](https://learn.microsoft.com/en-us/kusto/query/regex).
- [Cortex Actor](https://docs-cortex.paloaltonetworks.com/r/Cortex-XQL-Schema-Reference-Guide/Actor-Actor), [XQL reference](https://docs-cortex.paloaltonetworks.com/r/Cortex/Cortex-XQL-Command-Reference/Cortex-XQL-Command-Reference) and [first_value](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-3.x-Documentation/first_value).
- [Cortex start](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Start-an-XQL-Query), [results](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-XQL-Query-Results) and [lookup writes](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Add-or-update-data-in-a-lookup-dataset).

LOLDrivers CSVs and their independent hash queries remain under data/ and
queries/platform/loldrivers.*.
