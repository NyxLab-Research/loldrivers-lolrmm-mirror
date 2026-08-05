# Cortex XDR server synchronization

This deployment uses one Python script and either a user cron entry or a
systemd timer on Ubuntu 22.04/24.04. It does not require Docker, a database,
third-party Python packages, or a listening network port.

The job uses the official Cortex XDR APIs to create the `loldrivers_hashes` and
`lolrmm_domains` lookup datasets, apply incremental changes, remove stale rows,
and read the data back for verification.

Source hashes and row counts are checked before any tenant is modified. New and
changed rows are written before stale rows are removed. A deletion affecting
more than 25% of an existing lookup is blocked by default.

## Tenant API keys

Create one dedicated **Advanced** API key in each customer tenant. Use a custom
least-privilege role with the Data Management View/Edit permissions required
for lookup datasets. Copy the API FQDN and API key ID from the tenant's API Keys
page; do not derive the API hostname from the browser URL.
Keep Ubuntu time synchronization enabled because Advanced API authentication
includes a timestamp.

Each customer has one `.env` file. The files stay only on the Ubuntu server and
must never be committed to Git.

```dotenv
CORTEX_TENANT_NAME=customer-a
CORTEX_API_FQDN=api-customer-a.xdr.example.paloaltonetworks.com
CORTEX_API_KEY_ID=REPLACE_WITH_API_KEY_ID
CORTEX_API_KEY=REPLACE_WITH_API_KEY
CORTEX_API_KEY_TYPE=advanced
CORTEX_ENABLED=true
```

## User-home install without sudo

This option is suitable when an existing service account already has a working
user crontab. The public GitHub repository can be cloned and fetched over HTTPS
without a deploy key. Source data is downloaded from the public mirror on each
run, so unattended `git pull` is not required.

Create one private project directory, keeping configuration and state beside
the Git worktree rather than inside it:

```bash
install -d -m 0700 \
  "$HOME/loldrivers-lolrmm-mirror" \
  "$HOME/loldrivers-lolrmm-mirror/config/tenants" \
  "$HOME/loldrivers-lolrmm-mirror/state"
git clone --depth 1 \
  https://github.com/NyxLab-Research/loldrivers-lolrmm-mirror.git \
  "$HOME/loldrivers-lolrmm-mirror/repo"
install -m 0600 \
  "$HOME/loldrivers-lolrmm-mirror/repo/config/cortex_tenant.example.env" \
  "$HOME/loldrivers-lolrmm-mirror/config/tenants/customer-a.env"
```

Edit the tenant file, then run a read-only preview:

```bash
python3 "$HOME/loldrivers-lolrmm-mirror/repo/scripts/sync_cortex_lookups.py" \
  --env-dir "$HOME/loldrivers-lolrmm-mirror/config/tenants" \
  --tenant customer-a \
  --dry-run
```

Append a clearly marked block with `crontab -e`; preserve every existing entry.
The example below is for a server in `Asia/Hong_Kong`: 11:00 local time is
03:00 UTC, after the GitHub source refresh at 02:17 UTC.

```cron
# BEGIN LOLDRIVERS_LOLRMM_SYNC
0 11 * * * /usr/bin/flock -n "$HOME/loldrivers-lolrmm-mirror/state/sync.lock" /usr/bin/python3 "$HOME/loldrivers-lolrmm-mirror/repo/scripts/sync_cortex_lookups.py" --env-dir "$HOME/loldrivers-lolrmm-mirror/config/tenants" >> "$HOME/loldrivers-lolrmm-mirror/state/sync.log" 2>&1
# END LOLDRIVERS_LOLRMM_SYNC
```

`flock` prevents overlapping runs. Keep code updates manual and controlled:

```bash
cd "$HOME/loldrivers-lolrmm-mirror/repo"
git pull --ff-only
python3 -m unittest discover -s tests -v
```

## System service install on Ubuntu 22.04/24.04

Create a non-login service account and install the repository:

```bash
sudo useradd --system --user-group --home /nonexistent --shell /usr/sbin/nologin nyx-cortex-sync
sudo git clone --depth 1 \
  https://github.com/NyxLab-Research/loldrivers-lolrmm-mirror.git \
  /opt/nyxlab-cortex-sync
sudo chown -R root:root /opt/nyxlab-cortex-sync
sudo chmod -R go-w /opt/nyxlab-cortex-sync
```

Create the tenant directory. Files are owned by root, readable by the service
group, and not accessible by other users. The service account cannot edit them.

```bash
sudo install -d -o root -g nyx-cortex-sync -m 0750 \
  /etc/nyxlab-cortex-sync/tenants
sudo install -o root -g nyx-cortex-sync -m 0640 \
  /opt/nyxlab-cortex-sync/config/cortex_tenant.example.env \
  /etc/nyxlab-cortex-sync/tenants/customer-a.env
sudoedit /etc/nyxlab-cortex-sync/tenants/customer-a.env
sudo chown root:nyx-cortex-sync /etc/nyxlab-cortex-sync/tenants/customer-a.env
sudo chmod 0640 /etc/nyxlab-cortex-sync/tenants/customer-a.env
```

Add another customer by copying the example to another `.env` filename. Tenant
names inside the files must be unique.

Run a read-only preview for one tenant:

```bash
sudo -u nyx-cortex-sync \
  python3 /opt/nyxlab-cortex-sync/scripts/sync_cortex_lookups.py \
  --env-dir /etc/nyxlab-cortex-sync/tenants \
  --tenant customer-a \
  --dry-run
```

The preview reads the public mirror and the current Cortex lookups, then reports
how many rows would be created, updated, or removed. Run the same command without
`--dry-run` for the first controlled synchronization.

Install and enable the systemd units:

```bash
sudo install -m 0644 \
  /opt/nyxlab-cortex-sync/deploy/systemd/nyxlab-cortex-lookup-sync.service \
  /etc/systemd/system/
sudo install -m 0644 \
  /opt/nyxlab-cortex-sync/deploy/systemd/nyxlab-cortex-lookup-sync.timer \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start nyxlab-cortex-lookup-sync.service
sudo journalctl -u nyxlab-cortex-lookup-sync.service --no-pager
sudo systemctl enable --now nyxlab-cortex-lookup-sync.timer
```

The timer runs daily at 03:00 UTC with up to five minutes of randomized delay,
after the public mirror refresh at 02:17 UTC. A failed run is retried up to two
times, five minutes apart. Re-running is safe because updates use stable keys.

## Operations

```bash
systemctl list-timers nyxlab-cortex-lookup-sync.timer
systemctl status nyxlab-cortex-lookup-sync.service
journalctl -u nyxlab-cortex-lookup-sync.service --since today
```

To rotate a key, edit only that customer's `.env` file and run its dry run
again. To temporarily skip a customer, set `CORTEX_ENABLED=false`.

The server should use encrypted disks and encrypted backups. Restrict outbound
access to `raw.githubusercontent.com` and the configured Cortex API FQDNs where
practical. A server compromise can expose all readable tenant API keys, so keep
the keys separate, least-privileged, and covered by the normal rotation policy.

## Official Cortex XDR references

- [Add Dataset](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Add-Dataset)
- [Add or update data in a lookup dataset](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Add-or-update-data-in-a-lookup-dataset)
- [Get data from a lookup dataset](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Get-data-from-a-lookup-dataset)
- [Remove data from a lookup dataset](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Remove-data-from-a-lookup-dataset)
- [Create a new API key](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Create-a-new-API-key)
