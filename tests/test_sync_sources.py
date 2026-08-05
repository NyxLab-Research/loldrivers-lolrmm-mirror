import csv
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.sync_sources import (
    driver_rows,
    filter_rmm_rows,
    load_rmm_exclusions,
    rmm_rows,
    sync,
)


class SyncSourceTests(unittest.TestCase):
    def test_query_templates_use_the_supported_data_delivery_model(self):
        root = Path(__file__).resolve().parents[1]
        mde_driver_query = (root / "queries" / "mde" / "loldrivers.kql").read_text(encoding="utf-8")
        mde_rmm_query = (root / "queries" / "mde" / "lolrmm.kql").read_text(encoding="utf-8")
        cortex_driver_query = (root / "queries" / "cortex" / "loldrivers.xql").read_text(encoding="utf-8")
        cortex_rmm_query = (root / "queries" / "cortex" / "lolrmm.xql").read_text(encoding="utf-8")

        self.assertIn("loldrivers_hashes.csv", mde_driver_query)
        self.assertNotIn("ingestionMapping=@'", mde_driver_query)
        self.assertIn("Custom Detection frequency to Every hour", mde_driver_query)
        self.assertIn("ReportId", mde_driver_query)
        self.assertIn("Timestamp > ago(7d)", mde_rmm_query)
        self.assertIn("dataset = loldrivers_hashes", cortex_driver_query)
        cortex_code = "\n".join(
            line for line in cortex_driver_query.splitlines() if not line.lstrip().startswith("//")
        )
        self.assertNotIn("externaldata", cortex_code.lower())
        self.assertIn("dataset = lolrmm_domains", cortex_rmm_query)
        self.assertIn("config timeframe = 1h", cortex_driver_query)
        self.assertIn("config timeframe = 7d", cortex_rmm_query)
        self.assertIn("join conflict_strategy = left type = inner", cortex_driver_query)
        self.assertIn("join conflict_strategy = left type = inner", cortex_rmm_query)
        self.assertIn("action_module_sha256 = lol.sha256", cortex_driver_query)
        self.assertNotIn("action_file_sha256 = lol.sha256", cortex_driver_query)
        self.assertIn("category, verified, source_id, created", cortex_driver_query)
        self.assertIn("actor_process_image_name", cortex_driver_query)
        self.assertNotIn("lol.driver_name", cortex_driver_query)
        self.assertIn("remote_host = rmm.domain", cortex_rmm_query)
        self.assertIn("domain, rmm_tool, pattern", cortex_rmm_query)
        self.assertIn("actor_process_image_name", cortex_rmm_query)
        self.assertNotIn("rmm.rmm_tool", cortex_rmm_query)

    def test_driver_rows_deduplicate_sha256_and_validate_hashes(self):
        payload = json.dumps([
            {
                "Id": "driver-1",
                "Tags": ["one.sys"],
                "Category": "vulnerable driver",
                "Verified": "TRUE",
                "Created": "2026-01-01",
                "KnownVulnerableSamples": [{
                    "SHA256": "A" * 64,
                    "SHA1": "B" * 40,
                    "MD5": "C" * 32,
                    "Filename": "one.sys",
                }],
            },
            {
                "Id": "driver-2",
                "Tags": ["duplicate.sys"],
                "Category": "malicious",
                "Verified": "TRUE",
                "KnownVulnerableSamples": [{"SHA256": "a" * 64, "SHA1": "bad"}],
            },
        ]).encode()
        rows = driver_rows(payload)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sha256"], "a" * 64)
        self.assertIn("one.sys", rows[0]["driver_name"])
        self.assertIn("malicious", rows[0]["category"])

    def test_rmm_rows_normalize_wildcards_and_ports(self):
        payload = b"URI,RMM_Tool\n*.example.com,Example\nrelay-[a-f0-9]{8}.net.anydesk.com:443,AnyDesk\n"
        rows = rmm_rows(payload)
        by_pattern = {row["pattern"]: row for row in rows}
        self.assertEqual(by_pattern["*.example.com"]["domain"], "example.com")
        self.assertIn(".*", by_pattern["*.example.com"]["regex"])
        self.assertNotIn(":443", by_pattern["relay-[a-f0-9]{8}.net.anydesk.com:443"]["regex"])

    def test_rmm_exclusions_remove_only_exact_shared_domains(self):
        rows = rmm_rows(
            b"URI,RMM_Tool\n"
            b"github.com,Tool A\n"
            b"raw.githubusercontent.com,Tool B\n"
            b"nezhahq.github.io,Nezha\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            exclusions_file = Path(directory) / "exclusions.csv"
            exclusions_file.write_text(
                "domain,reason\n"
                "github.com,Shared platform\n"
                "raw.githubusercontent.com,Shared content hosting\n",
                encoding="utf-8",
            )
            effective, excluded = filter_rmm_rows(rows, load_rmm_exclusions(exclusions_file))

        self.assertEqual([row["domain"] for row in effective], ["nezhahq.github.io"])
        self.assertEqual({row["domain"] for row in excluded}, {"github.com", "raw.githubusercontent.com"})
        self.assertTrue(all(row["exclusion_reason"] for row in excluded))

    def test_sync_writes_raw_and_derived_files(self):
        drivers = b'[{"Id":"1","Tags":["x.sys"],"Category":"malicious","Verified":"TRUE","KnownVulnerableSamples":[{"SHA256":"' + b'a' * 64 + b'"}]}]'
        rmm = b"URI,RMM_Tool\ngithub.com,Generic\nnezhahq.github.io,Nezha\n"
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory) / "data"
            exclusions_file = Path(directory) / "exclusions.csv"
            exclusions_file.write_text(
                "domain,reason\ngithub.com,Shared platform\n",
                encoding="utf-8",
            )
            with patch("scripts.sync_sources.fetch", side_effect=[drivers, rmm]):
                summary = sync(output_dir, rmm_exclusions_file=exclusions_file)
            self.assertEqual(summary["driver_hash_rows"], 1)
            self.assertEqual(summary["rmm_upstream_rows"], 2)
            self.assertEqual(summary["rmm_excluded_rows"], 1)
            self.assertEqual(summary["rmm_effective_rows"], 1)
            self.assertIn("github.com", (output_dir / "raw" / "rmm_domains.csv").read_text())
            with (output_dir / "lolrmm_domains.csv").open(newline="", encoding="utf-8") as handle:
                self.assertEqual(next(csv.DictReader(handle))["domain"], "nezhahq.github.io")
            manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["rmm_excluded_rows"], 1)
            self.assertEqual(
                manifest["loldrivers_csv_sha256"],
                hashlib.sha256((output_dir / "loldrivers_hashes.csv").read_bytes()).hexdigest(),
            )
            self.assertEqual(
                manifest["lolrmm_csv_sha256"],
                hashlib.sha256((output_dir / "lolrmm_domains.csv").read_bytes()).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
