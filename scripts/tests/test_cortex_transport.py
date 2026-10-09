import gzip
import io
from http.client import IncompleteRead
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import cortex_lookup as api

class TransportTests(unittest.TestCase):
    def test_compressed_json_has_a_decompressed_size_limit(self):
        response=io.BytesIO(gzip.compress(b'{"reply":{}}'));response.headers={'Content-Encoding':'gzip'}
        self.assertEqual(api.read_limited(response),b'{"reply":{}}')
        response=io.BytesIO(gzip.compress(b'x'*1000));response.headers={'Content-Encoding':'gzip'}
        with self.assertRaises(api.SyncError):api.read_limited(response,100)
    def test_incomplete_lookup_reads_retry_but_mutations_do_not(self):
        client=api.CortexClient(api.Tenant('fixture','fixture.paloaltonetworks.com','1','fixture-key','standard'),1)
        with patch.object(client,'_post_once',side_effect=[IncompleteRead(b'partial'),{'reply':{}}]) as call,patch.object(api.time,'sleep'):
            self.assertEqual(client.post('/public_api/v1/xql/lookups/get_data',{}),{'reply':{}})
            self.assertEqual(call.call_count,2)
        with patch.object(client,'_post_once',side_effect=IncompleteRead(b'partial')) as call:
            with self.assertRaises(IncompleteRead):client.post('/public_api/v1/xql/lookups/add_data',{})
            self.assertEqual(call.call_count,1)

if __name__=='__main__':unittest.main()
