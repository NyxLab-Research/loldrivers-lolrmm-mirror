import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.sync_cortex_lookups import (
    DATASET_SPECS,
    LOOKUP_READ_LIMIT,
    CortexClient,
    MutationLimiter,
    Settings,
    SyncError,
    Tenant,
    advanced_auth_headers,
    build_plan,
    enforce_delete_guard,
    load_tenants,
    load_source_data,
    sha256_bytes,
    sync_dataset,
)


class FakeCortexClient:
    def __init__(self, rows=None):
        self.datasets = {name: [dict(row) for row in values] for name, values in (rows or {}).items()}
        self.created = []
        self.upsert_calls = []
        self.remove_calls = []

    def get_rows(self, dataset_name):
        return [dict(row) for row in self.datasets.get(dataset_name, [])]

    def get_dataset_names(self):
        return {name.lower() for name in self.datasets}

    def add_dataset(self, spec):
        self.created.append(spec.name)
        self.datasets[spec.name] = []

    def add_rows(self, spec, rows):
        self.upsert_calls.append((spec.name, [dict(row) for row in rows]))
        current = {
            tuple(row[field] for field in spec.key_fields): dict(row)
            for row in self.datasets.get(spec.name, [])
        }
        for row in rows:
            current[tuple(row[field] for field in spec.key_fields)] = dict(row)
        self.datasets[spec.name] = list(current.values())

    def remove_rows(self, spec, filters):
        self.remove_calls.append((spec.name, [dict(row) for row in filters]))
        stale = {tuple(row[field] for field in spec.key_fields) for row in filters}
        self.datasets[spec.name] = [
            row
            for row in self.datasets.get(spec.name, [])
            if tuple(row[field] for field in spec.key_fields) not in stale
        ]


class CortexLookupSyncTests(unittest.TestCase):
    def test_get_dataset_names_accepts_nested_core_api_response(self):
        tenant = Tenant("customer", "api.example.test", "42", "secret", "advanced")
        client = CortexClient(tenant, timeout=1)
        response = {"response": {"reply": [{"Dataset Name": "Example_Lookup"}]}}

        with patch.object(client, "post", return_value=response):
            names = client.get_dataset_names()

        self.assertEqual(names, {"example_lookup"})

    def test_get_rows_requests_and_validates_the_complete_lookup(self):
        tenant = Tenant("customer", "api.example.test", "42", "secret", "advanced")
        client = CortexClient(tenant, timeout=1)
        rows = [{"domain": "a.example"}]
        response = {"reply": {"data": rows, "total_count": "1"}}

        with patch.object(client, "post", return_value=response) as post:
            actual = client.get_rows("example_lookup")

        self.assertEqual(actual, rows)
        post.assert_called_once_with(
            "/public_api/v1/xql/lookups/get_data",
            {"dataset_name": "example_lookup", "filters": [], "limit": LOOKUP_READ_LIMIT},
        )

    def test_add_rows_uses_official_lookup_payload(self):
        spec = DATASET_SPECS[1]
        tenant = Tenant("customer", "api.example.test", "42", "secret", "advanced")
        client = CortexClient(tenant, timeout=1)
        rows = [{"domain": "a.example", "rmm_tool": "A", "pattern": "a.example", "regex": "a"}]

        with patch.object(client, "post", return_value={}) as post:
            client.add_rows(spec, rows)

        post.assert_called_once_with(
            "/public_api/v1/xql/lookups/add_data",
            {"dataset_name": spec.name, "data": rows},
        )

    def test_advanced_auth_headers_match_official_signature_algorithm(self):
        tenant = Tenant("customer", "api.example.test", "42", "secret", "advanced")
        headers = advanced_auth_headers(tenant, nonce="A" * 64, timestamp_ms=1234567890)

        expected = hashlib.sha256(("secret" + "A" * 64 + "1234567890").encode()).hexdigest()
        self.assertEqual(headers["Authorization"], expected)
        self.assertEqual(headers["x-xdr-auth-id"], "42")
        self.assertEqual(headers["x-xdr-nonce"], "A" * 64)
        self.assertEqual(headers["x-xdr-timestamp"], "1234567890")

    def test_plan_updates_changed_rows_and_removes_only_stale_keys(self):
        spec = DATASET_SPECS[1]
        desired = (
            {"domain": "a.example", "rmm_tool": "A", "pattern": "a.example", "regex": "new"},
            {"domain": "b.example", "rmm_tool": "B", "pattern": "b.example", "regex": "same"},
        )
        current = (
            {"domain": "a.example", "rmm_tool": "A", "pattern": "a.example", "regex": "old"},
            {"domain": "stale.example", "rmm_tool": "S", "pattern": "stale.example", "regex": "stale"},
        )

        plan = build_plan(desired, current, spec, create_dataset=False)

        self.assertEqual(plan.upsert_rows, (desired[0], desired[1]))
        self.assertEqual(
            plan.stale_keys,
            ({"pattern": "stale.example", "rmm_tool": "S"},),
        )

    def test_delete_guard_blocks_large_removal(self):
        spec = DATASET_SPECS[1]
        current = tuple(
            {
                "domain": f"{number}.example",
                "rmm_tool": "Tool",
                "pattern": f"{number}.example",
                "regex": "x",
            }
            for number in range(4)
        )
        plan = build_plan(current[:1], current, spec, create_dataset=False)

        with self.assertRaises(SyncError):
            enforce_delete_guard(plan, spec, max_delete_fraction=0.25, allow_large_delete=False)
        enforce_delete_guard(plan, spec, max_delete_fraction=0.25, allow_large_delete=True)

    def test_sync_dataset_creates_missing_lookup_and_verifies_rows(self):
        spec = DATASET_SPECS[1]
        desired = (
            {"domain": "a.example", "rmm_tool": "A", "pattern": "a.example", "regex": "a"},
            {"domain": "b.example", "rmm_tool": "B", "pattern": "b.example", "regex": "b"},
        )
        client = FakeCortexClient()

        plan = sync_dataset(
            client=client,
            spec=spec,
            desired_rows=desired,
            dataset_exists=False,
            limiter=MutationLimiter(0),
            max_delete_fraction=0.25,
            dry_run=False,
            allow_large_delete=False,
        )

        self.assertTrue(plan.create_dataset)
        self.assertEqual(client.created, [spec.name])
        self.assertEqual(client.datasets[spec.name], list(desired))

    def test_sync_dataset_upserts_before_removing_stale_rows(self):
        spec = DATASET_SPECS[1]
        current = {
            spec.name: [
                {"domain": "old.example", "rmm_tool": "Old", "pattern": "old.example", "regex": "old"},
            ]
        }
        desired = (
            {"domain": "new.example", "rmm_tool": "New", "pattern": "new.example", "regex": "new"},
        )
        client = FakeCortexClient(current)

        sync_dataset(
            client=client,
            spec=spec,
            desired_rows=desired,
            dataset_exists=True,
            limiter=MutationLimiter(0),
            max_delete_fraction=1,
            dry_run=False,
            allow_large_delete=False,
        )

        self.assertEqual(len(client.upsert_calls), 1)
        self.assertEqual(len(client.remove_calls), 1)
        self.assertEqual(client.datasets[spec.name], list(desired))

    def test_local_source_requires_manifest_hashes_and_counts(self):
        drivers = (
            "sha256,sha1,md5,driver_name,category,verified,source_id,created\n"
            + "a" * 64
            + ",,,,,,,\n"
        ).encode()
        rmm = b"domain,rmm_tool,pattern,regex\na.example,A,a.example,a\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env_dir = root / "tenants"
            env_dir.mkdir(mode=0o700)
            (env_dir / "test.env").write_text(
                "CORTEX_TENANT_NAME=test\n"
                "CORTEX_API_FQDN=api.example.test\n"
                "CORTEX_API_KEY_ID=1\n"
                "CORTEX_API_KEY='secret'\n",
                encoding="utf-8",
            )
            (root / "loldrivers_hashes.csv").write_bytes(drivers)
            (root / "lolrmm_domains.csv").write_bytes(rmm)
            (root / "manifest.json").write_text(
                "{\n"
                '  "driver_hash_rows": 1,\n'
                '  "rmm_effective_rows": 1,\n'
                f'  "loldrivers_csv_sha256": "{sha256_bytes(drivers)}",\n'
                f'  "lolrmm_csv_sha256": "{sha256_bytes(rmm)}"\n'
                "}\n",
                encoding="utf-8",
            )

            tenants = load_tenants(env_dir)
            settings = Settings(
                source_base_url="https://example.test/data",
                request_timeout_seconds=120,
                mutation_interval_seconds=0,
                max_delete_fraction=0.25,
            )
            datasets = load_source_data(settings, root)

        self.assertEqual(tenants[0].api_key, "secret")
        self.assertEqual(len(datasets["loldrivers_hashes"]), 1)
        self.assertEqual(len(datasets["lolrmm_domains"]), 1)


if __name__ == "__main__":
    unittest.main()
