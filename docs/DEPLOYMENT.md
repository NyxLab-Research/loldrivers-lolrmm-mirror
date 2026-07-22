# Deployment

## GitHub mirror

1. The configured public mirror is
   `NyxLab-Research/loldrivers-lolrmm-mirror`.
2. Enable Actions and allow the workflow to write repository contents. The
   scheduled workflow runs daily at 02:17 UTC; `workflow_dispatch` is available
   for an immediate refresh.
3. The MDE query files already point to this public repository. The raw URL
   must remain reachable by the customer's Defender tenant. If the repository
   is later made private, `externaldata()` cannot authenticate to it; use an
   approved public read-only mirror or host the CSV at an endpoint supported by
   the tenant.

The workflow preserves the upstream files under `data/raw/` and produces:

- `data/loldrivers_hashes.csv`: one deterministic row per unique SHA256 sample.
- `data/lolrmm_domains.csv`: normalized domains plus the original pattern and a
  regex representation.
- `data/manifest.json`: source URLs, hashes, and row counts for auditability.

## Microsoft Defender for Endpoint

Paste the relevant file under `queries/mde/` into Advanced Hunting after
replacing the repository placeholder. The LOLDrivers query uses a flat CSV and
two joins (SHA256/SHA1), which avoids the published query's invalid
`ingestionMapping=@'...'` construct. The RMM query uses `parse_url()` and
suffix matching and keeps a visible `SanctionRMM` allowlist for approved tools.

## Cortex XDR

Cortex XQL does not provide KQL's `externaldata()` URL reader. Palo Alto's
official XQL documentation describes lookup datasets as CSV/TSV/JSON data that
is imported into Cortex XDR and then joined with `join`. Import these files as
lookup datasets (replace existing data on every refresh):

| File | Lookup dataset name |
| --- | --- |
| `data/loldrivers_hashes.csv` | `loldrivers_hashes` |
| `data/lolrmm_domains.csv` | `lolrmm_domains` |

The current documented UI path is **Settings -> Configurations -> Data
Management -> Dataset Management -> + Lookup**. Cortex documents a 30 MB UI
upload limit (50 MB through XQL/API) and supports replacing an existing lookup.
For automatic customer-side refresh, download the GitHub CSV on a controlled
host and use the tenant's supported lookup/API or Files and Folders Collector;
do not point XQL directly at GitHub.

The XQL queries use documented fields `action_module_sha256`,
`action_file_sha256`, and `action_external_hostname`, and the documented `join`
stage. Driver matching is exact SHA256. The module-hash branch is the closer
equivalent to a driver/module load; the file-hash branch is broader and can
also report a known driver that was written or accessed but not loaded. Remove
the file-hash branch if the use case requires only module-load telemetry.

RMM matching is exact domain or a subdomain suffix. Replace the placeholder in
the Cortex query's `not in` filter with approved remote hosts. Suffix matching
is intentionally broad for hunting and can match a crafted hostname that
contains a known RMM suffix before additional labels; review and allowlist
results before turning the hunt into a correlation/prevention rule.

## Official references

- [Cortex XDR `join` stage](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-3.x-Documentation/join)
- [Lookup datasets](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-3.x-Documentation/Lookup-datasets)
- [Import a lookup dataset](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-3.x-Documentation/Import-a-lookup-dataset)
- [XQL supported operators](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-3.x-Documentation/Supported-operators)
- [Cortex XDR XQL datasets](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-3.x-Documentation/Datasets-and-presets)
