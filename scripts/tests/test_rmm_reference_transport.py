import io
import json
from http.client import RemoteDisconnected, IncompleteRead
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sync_rmm_references as sync


class ReferenceTransportTests(unittest.TestCase):
    def test_transient_downloads_retry_and_keep_one_revision(self):
        revision = 'a' * 40
        for failure in (RemoteDisconnected('closed'), IncompleteRead(b'partial')):
            requested = []

            def fetch(request, **kwargs):
                url = request.full_url
                requested.append(url)
                if len(requested) == 1:
                    raise failure
                if url.endswith('/commits/main'):
                    payload = json.dumps({'sha': revision}).encode()
                else:
                    self.assertIn('/' + revision + '/data/', url)
                    payload = (sync.ref.ROOT / 'data' / url.rsplit('/', 1)[-1]).read_bytes()
                response = io.BytesIO(payload)
                response.headers = {}
                return response

            with patch.object(sync, 'urlopen', side_effect=fetch), patch.object(sync.time, 'sleep'):
                result = sync.published_references()
            self.assertEqual(result['commit'], revision)
            self.assertGreater(len(result['general']), 1)
            self.assertEqual(requested[0], requested[1])
            self.assertEqual(len(requested), 5)

    def test_invalid_reference_is_not_retried_or_activated(self):
        response = io.BytesIO(b'not JSON')
        response.headers = {}
        with patch.object(sync, 'urlopen', return_value=response) as fetch:
            with self.assertRaises(ValueError):
                sync.published_references()
            self.assertEqual(fetch.call_count, 1)


if __name__ == '__main__':
    unittest.main()
