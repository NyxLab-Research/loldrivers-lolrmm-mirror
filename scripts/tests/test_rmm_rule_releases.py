import csv
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import refresh_rmm_rules as release
import rmm_reference_data as ref


class ReleaseTests(unittest.TestCase):
    def test_immutable_release_advances_for_change_or_deletion_but_not_reordering(self):
        def compile_rows(source):
            return ref.seal([dict(row_id=source['release']+':'+v, record_type='condition', value=v)
                             for v in source['values']], ref.POLICY_FIELDS, source['release'])
        with tempfile.TemporaryDirectory() as tmp:
            path, feed = Path(tmp)/'source.json', Path(tmp)/'feed.csv'
            original = dict(release='000002', values=['a','b'])
            feed.write_bytes(ref.csv_bytes(compile_rows(original), ref.POLICY_FIELDS))
            for values, requested, expected in [(['b','a'],'000002','000002'),
                                                (['a','c'],'000002','000003'),
                                                (['a'],'000001','000003'),
                                                (['a','b'],'000005','000005')]:
                path.write_text(json.dumps(dict(release=requested, values=values)))
                actual = release.refresh_source(path,feed,compile_rows,lambda rows: ref.validate(rows,ref.POLICY_FIELDS))
                self.assertEqual(actual,expected)

    def test_incomplete_previous_release_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, feed = Path(tmp)/'source.json', Path(tmp)/'feed.csv'
            path.write_text('{"release":"000001"}')
            feed.write_bytes(ref.csv_bytes([],ref.POLICY_FIELDS))
            with self.assertRaises(ValueError):
                release.refresh_source(path,feed,lambda source: [],lambda rows: ref.validate(rows,ref.POLICY_FIELDS))


if __name__ == '__main__': unittest.main()
