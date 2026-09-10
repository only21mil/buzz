import importlib.util
import io
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('broker', Path(__file__).parents[1] / 'broker.py')
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)


class BrokerTests(unittest.TestCase):
    def test_bounded_log_keeps_exact_prefix_and_counts_discarded_bytes(self):
        kept = bytearray()
        with patch.object(broker, 'LOG_CAP', 4), patch.object(broker.os, 'read', side_effect=[b'abc', b'def', BlockingIOError()]):
            count = broker.drain_log(99, kept, 0)
        self.assertEqual(bytes(kept), b'abcd')
        self.assertEqual(count, 6)

    def test_continuous_log_flood_cannot_starve_deadline_checks(self):
        with patch.object(broker.os, 'read', return_value=b'x' * 65536) as read:
            kept = bytearray()
            count = broker.drain_log(99, kept, 0)
        self.assertEqual(read.call_count, 16)
        self.assertEqual(count, 1024 * 1024)
        self.assertEqual(len(kept), broker.LOG_CAP)

    def test_log_metadata_binds_exact_retained_bytes(self):
        request = {'run_id': 'a' * 32, 'attempt': 1}
        with tempfile.TemporaryDirectory() as directory, patch.object(broker, 'STATE', Path(directory)), patch.object(broker, 'protected'):
            broker.write_new(broker.record_path(request, 'log'), b'build\n')
            self.assertEqual(broker.log_metadata(request), {'sha256': hashlib.sha256(b'build\n').hexdigest(), 'byte_length': 6, 'cap_bytes': broker.LOG_CAP})

    def test_read_frame_refuses_truncation_and_suffix(self):
        self.assertEqual(broker.read_frame(io.BytesIO(b'x' * 992)), b'x' * 992)
        for size in (0, 991, 993, 1024):
            with self.assertRaises(ValueError):
                broker.read_frame(io.BytesIO(b'x' * size))

    def test_attempt_replay_cannot_replace_retained_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'record'
            broker.write_new(path, b'first')
            with self.assertRaises(FileExistsError):
                broker.write_new(path, b'second')
            self.assertEqual(path.read_bytes(), b'first')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_record_rejects_other_admission_for_same_run_attempt(self):
        request = {'run_id': 'a' * 32, 'attempt': 1, 'admission_message_digest': 'b' * 64}
        with tempfile.TemporaryDirectory() as directory, patch.object(broker, 'STATE', Path(directory)):
            broker.write_new(broker.record_path(request, 'admitted'), json.dumps(request).encode())
            with patch.object(broker, 'protected'):
                broker.load_record(request)
                with self.assertRaises(ValueError):
                    broker.load_record(dict(request, admission_message_digest='c' * 64))

    def test_public_wire_header_does_not_select_replay_path(self):
        request = {'run_id': 'a' * 32, 'attempt': 2}
        self.assertEqual(broker.record_path(request, 'admitted').name, 'a' * 32 + '-2.admitted')

    def test_crash_record_blocks_new_work_until_cleanup_proven(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(broker, 'STATE', Path(directory)), patch.object(broker, 'protected'):
            prior = Path(directory) / ('a' * 32 + '-1.admitted')
            prior.write_text('{}')
            with self.assertRaises(ValueError):
                broker.require_no_unfinished()
            receipt = prior.with_suffix('.receipt')
            receipt.write_text('{"cleanup_complete": false}')
            with self.assertRaises(ValueError):
                broker.require_no_unfinished()
            receipt.write_text('{"cleanup_complete": true}')
            broker.require_no_unfinished()


if __name__ == '__main__':
    unittest.main()
