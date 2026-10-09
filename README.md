# LOLDrivers + LOLRMM Detections

Normalized LOLDrivers and LOLRMM datasets with detection and hunting queries
for Microsoft Defender for Endpoint and Cortex XDR.

The data is synchronized from the public
[LOLDrivers](https://www.loldrivers.io/) and
[LOLRMM](https://github.com/magicsword-io/LOLRMM) projects.

## RMM reports

The default MDE and Cortex queries report connections to known RMM-related
domains. A domain hit is an investigation lead, not proof of an installed RMM
product or a completed remote session. `EventCount` counts source events.

The report removes three narrowly identified categories:

- Standard Chrome, Edge, Firefox, Vivaldi and QQ Browser processes in expected
  installation paths with valid matching signer evidence.
- Known Sogou input components connecting to `oth.eve.mdt.qq.com`, with matching
  product directories and valid signer evidence, including custom installations.
- Signed Endpoint Central / Desktop Central agents in identified Windows and
  macOS directories, excluded by **report scope**. These products can provide
  remote control; exclusion is not a verdict that they lack RMM capability.

Missing or invalid signature evidence keeps an entry in the report. Microsoft,
Google, Tencent, Zoho and shared domains are not excluded as whole vendors.
Quick Assist, its WebView2 traffic, Chrome Remote Desktop and independent
ZohoMeeting components are outside the default exclusions.

MDE normalizes URLs and bare FQDNs, enriches signatures by device ID and process
SHA1, and retains hashes, paths, parent processes, accounts and network context.
Company/product version metadata is not signer evidence. Certificates use the
latest observation for the same device/SHA1 within 30 days; they do not establish
the signing state at every historical connection. SHA256 may be unavailable.

Both platforms match the exact IOC domain or a complete subdomain suffix.
Multiple IOC/tool associations merge into one activity row; event counts are
computed before that join. Collected usernames, commands, IPs, signatures and
process IDs are independent sets, without positional correspondence. Entries
whose exclusion decisions differ remain separate even for the same file hash.

## Generate queries

Python 3.10 or later is sufficient; no packages or credentials are needed.

```console
python scripts/build_rmm_queries.py
python scripts/build_rmm_queries.py --check
```

The generator validates `rules/rmm_report_exclusions.json` and updates
`queries/mde/lolrmm.kql` and `queries/cortex/lolrmm.xql` from shared templates.
Edit the rules/templates, then regenerate; do not maintain independent exclusions
in the two generated files. CI checks that committed defaults match their inputs.
JSON schemas describe the structure; runtime validation additionally checks field,
operator, hash, directory-boundary and configuration-conflict constraints.

The MDE prefilter and final IOC join read the same materialized source. Search
terms are grouped in sets of at most 120. Uncovered, unsafe or excessive term
sets disable the incomplete prefilter, rather than silently omit new domains.
That fallback can cost more resources; use smaller windows if needed.

Default report windows remain seven days. For **Cortex validation, start at one
hour**, extend to one day only when needed, and check actual CU consumption.
The query requires the existing `lolrmm_domains` lookup; no exclusion lookup is
required. Cortex settings share one first stage, for example
`config case_sensitive = true timeframe = 7d`; do not split them into separate
`config` stages. API validation should preserve the complete generated header
and supply a matching explicit API timeframe of one hour. Poll/download an
existing query ID rather than submit it again. Fetch a stream when results
exceed 1,000 rows.
For API exports, normalize timestamps and numeric strings, treat omitted null
fields as unknown, and sort the full downloaded result by `last_seen` locally.
Native checks observed non-monotonic timestamp order in large audit/baseline
API responses even with the query's final `sort` stage; the cause is unconfirmed.

```console
python scripts/build_rmm_queries.py --platform cortex --timeframe 1h --output-dir output/rmm/test
python scripts/build_rmm_queries.py --mode audit --timeframe 1h --output-dir output/rmm/audit
python scripts/build_rmm_queries.py --mode baseline --output-dir output/rmm/baseline
```

`report` keeps retained activities/associations. `audit` includes exclusions and
the rule IDs that explain each decision. `baseline` keeps the parsing, identity
and domain-boundary fixes while disabling all report exclusions. Audit rows can
split by decision; do not sum event counts across separately retained/excluded
IOC associations to calculate total network events.

## Optional customer whitelist

Copy `rules/rmm_customer.example.json` to the ignored
`config/rmm_whitelists/<customer>.json` directory. An empty or absent configuration
uses the common defaults; customers do not need to provide a software inventory.
`rules/rmm_customer.whitelist.example.json` demonstrates a scoped rule using
fictional values. Customer queries and previews must be saved under ignored
`output/` or `tmp/` directories. The generator rejects private outputs in public
query directories.
Private generation also saves `rmm_generation_manifest.json` with query hashes,
rule reasons and the exact policy/customer snapshots. Use a separate directory
for each report run to preserve its evidence. Offline previews include the same
snapshots for later review and rollback.

```console
python scripts/build_rmm_queries.py --customer config/rmm_whitelists/example.json --output-dir output/rmm/example
```

- Conditions within a rule are ANDed. `in` values and multiple rules are ORed.
- `disabled_default_rules` disables selected common rule IDs for that customer.
- `retain_rules` overrides matching common exclusions. Explicit customer
  whitelist rules still apply. Identical retain/whitelist predicates are rejected.
- `target: activity` removes the activity and its IOC associations; it supports
  device, process, path, signer, signature, hash and actual-host conditions.
- `target: association` removes only the matching IOC domain/tool association.
  Other matches remain. Use scalar `matched_domain`/`rmm_tool` conditions, with
  optional device ID, process name/path/hash and actual-host restrictions.
  Signer/signature/device-name predicates belong in activity rules, where the
  original evidence is available.
- `exact` matches a host; `domain_suffix` includes the domain and its true
  subdomains. Neither is arbitrary substring matching.
- `path_prefix` must end with a directory separator. `glob` supports only `*`
  and `?`; it is a full-path match. Windows paths/names ignore case; Unix paths
  preserve it. Cortex internally normalizes Windows separators to `/`.
  XQL sets `case_sensitive=true` and normalizes the intended insensitive fields;
  verify these predicates per tenant because server settings can override query
  case sensitivity. Do not change tenant-wide settings as part of report generation.
- `expires_at` must include a timezone and whole seconds. It is checked at
  query execution, so a saved query does not permanently freeze its whitelist.
- Missing fields do not satisfy conditions. Empty rules, unsupported operators
  and malformed hashes are rejected. SHA1 conditions are MDE-only; generate
  only MDE when using them. Cortex supports Actor SHA256.

Review a proposed configuration against an existing normalized export without
calling either platform:

```console
python scripts/build_rmm_queries.py --customer config/rmm_whitelists/example.json --preview output/rmm/normalized.json --preview-output output/rmm/example-preview.json
```

Normalized input is an array of objects with `device_id`, `remote_host`,
`process_name`, `process_path`, `sha1`, `sha256`, `signature_valid`, `signer`,
`matched_domain`, scalar `rmm_tool` and integer `event_count`.
Signature evidence can be a consistent signer array; use `null` for unknown
signature validity. Expand separate domain/tool associations into separate rows
with the same activity event count. The preview merges activity counts once and
rejects contradictory counts for duplicate activity keys. It saves detailed
reasons locally; it never creates tenant exclusions or uploads a whitelist.

Rollback can disable a rule/customer entry and regenerate the query. To recover
a complete report, prefer `--mode baseline` so the URL parsing fix remains.

## Official references

Query fields and expressions are based on the vendors' documentation:

- [MDE network events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
  and [certificate observations](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefilecertificateinfo-table).
- [Graph hunting API](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0),
  [KQL parse_url](https://learn.microsoft.com/en-us/kusto/query/parse-url-function),
  [has_any](https://learn.microsoft.com/en-us/kusto/query/has-any-operator),
  [array_slice](https://learn.microsoft.com/en-us/kusto/query/array-slice-function),
  [broadcast join](https://learn.microsoft.com/en-us/kusto/query/broadcast-join)
  and [regex/string quoting](https://learn.microsoft.com/en-us/kusto/query/regex).
- [Cortex Actor schema](https://docs-cortex.paloaltonetworks.com/r/Cortex-XQL-Schema-Reference-Guide/Actor-Actor),
  [XDR_DATA schema](https://docs-cortex.paloaltonetworks.com/r/Cortex-XQL-Schema-Reference-Guide/XDR_DATA-Fields)
  and [XQL command/function reference](https://docs-cortex.paloaltonetworks.com/r/Cortex/Cortex-XQL-Command-Reference/Cortex-XQL-Command-Reference)
  (`comp`, `first`, `replex`, `wildcard_match`, JSON scalar arrays, `arraymap`,
  `current_time` and `parse_timestamp`). Cortex `Signed` has value `1`.
- [Cortex query execution](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Start-an-XQL-Query),
  [results](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-XQL-Query-Results)
  and [stream](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-XQL-query-results-Stream).
- [Cortex config stage](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-3.x-Documentation/config)
  and [combined configuration example](https://docs-cortex.paloaltonetworks.com/r/Cortex/Cortex-XQL-Command-Reference/Example-7-Host-users-to-groups-preset).
- [Quick Assist](https://learn.microsoft.com/en-us/windows/client-management/client-tools/quick-assist),
  [ManageEngine communication](https://www.manageengine.com/uk/products/desktop-central/help/cloud/server/domains-required-for-agent-communication.html)
  and [agent directories](https://www.manageengine.com/products/desktop-central/logs-how-to.html).

Customer exports, credentials and validation evidence remain local and ignored
by Git. Native API checks are read-only hunting operations.
