import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.sync_sources import driver_rows, rmm_rows, sync


class SyncSourceTests(unittest.TestCase):
    def test_query_templates_use_the_supported_data_delivery_model(self):
        root = Path(__file__).resolve().parents[1]
        mde_driver_query = (root / "queries" / "mde" / "loldrivers.kql").read_text(encoding="utf-8")
        cortex_driver_query = (root / "queries" / "cortex" / "loldrivers.xql").read_text(encoding="utf-8")
        cortex_rmm_query = (root / "queries" / "cortex" / "lolrmm.xql").read_text(encoding="utf-8")

        self.assertIn("loldrivers_hashes.csv", mde_driver_query)
        self.assertNotIn("ingestionMapping=@'", mde_driver_query)
        self.assertIn("dataset = loldrivers_hashes", cortex_driver_query)
        cortex_code = "\n".join(
            line for line in cortex_driver_query.splitlines() if not line.lstrip().startswith("//")
        )
        self.assertNotIn("externaldata", cortex_code.lower())
        self.assertIn("dataset = lolrmm_domains", cortex_rmm_query)

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

    def test_sync_writes_raw_and_derived_files(self):
        drivers = b'[{"Id":"1","Tags":["x.sys"],"Category":"malicious","Verified":"TRUE","KnownVulnerableSamples":[{"SHA256":"' + b'a' * 64 + b'"}]}]'
        rmm = b"URI,RMM_Tool\nexample.com,Example\n"
        with tempfile.TemporaryDirectory() as directory:
            with patch("scripts.sync_sources.fetch", side_effect=[drivers, rmm]):
                summary = sync(Path(directory))
            self.assertEqual(summary["driver_hash_rows"], 1)
            self.assertTrue((Path(directory) / "raw" / "drivers.json").exists())
            with (Path(directory) / "lolrmm_domains.csv").open(newline="", encoding="utf-8") as handle:
                self.assertEqual(next(csv.DictReader(handle))["domain"], "example.com")


if __name__ == "__main__":
    unittest.main()
