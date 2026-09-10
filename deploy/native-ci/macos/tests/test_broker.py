import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('broker', Path(__file__).parents[1] / 'broker.py')
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)


class BrokerTests(unittest.TestCase):
    def test_read_frame_refuses_truncation_and_suffix(self):
        self.assertEqual(broker.read_frame(io.BytesIO(b'x' * 512)), b'x' * 512)
        for size in (0, 511, 513, 1024):
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


if __name__ == '__main__':
    unittest.main()
