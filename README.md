# LOLDrivers + LOLRMM customer detections

This repository mirrors the LOLDrivers and LOLRMM open-source feeds into an
organization-controlled GitHub repository and supplies corresponding hunting
queries for Microsoft Defender for Endpoint (MDE) and Cortex XDR.

Run the initial refresh locally with:

```powershell
python scripts/sync_sources.py --output-dir data
python -m unittest discover -s tests -v
```

Then publish this directory to the chosen GitHub repository and enable the
scheduled workflow. Deployment instructions, platform limitations, and
official Cortex XDR references are in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

The configured mirror is
[NyxLab-Research/loldrivers-lolrmm-mirror](https://github.com/NyxLab-Research/loldrivers-lolrmm-mirror).
MDE queries already point to this repository. Cortex XDR queries use imported
lookup datasets and therefore do not contain a GitHub URL; XQL has no
`externaldata()` equivalent. Multi-tenant Cortex lookup maintenance can be
automated from Ubuntu using the official APIs and the one-shot synchronizer in
`scripts/sync_cortex_lookups.py`; see
[`docs/CORTEX_SERVER_SYNC.md`](docs/CORTEX_SERVER_SYNC.md).

Shared infrastructure domains that are too noisy for domain-only RMM hunting
are maintained centrally in
[`config/lolrmm_domain_exclusions.csv`](config/lolrmm_domain_exclusions.csv).
The upstream raw CSV remains unchanged for auditability.
