import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('watcher', Path(__file__).parents[1] / 'watch-and-begin.py')
watcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watcher)


class WatchTests(unittest.TestCase):
    def test_stages_exact_bytes_then_acknowledges_as_existing_socket_peer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'attempt').mkdir()
            request = json.dumps({'id': 'ab' * 32}).encode() + b'\n'
            result = json.dumps({'queued_event_id': 'cd' * 32}).encode() + b'\n'
            args = ['watch', str(root / 'attempt'), 'aa' * 32, 'https://relay.example', '30', str(root / 'ack.json')]
            with patch.object(watcher.sys, 'argv', args), patch.object(watcher.os, 'geteuid', return_value=0), patch.object(watcher, 'protected_directory'), patch.object(watcher, 'STORE', root / 'stores'), patch.object(watcher.os, 'chown') as chown, patch.object(watcher.subprocess, 'run', side_effect=[SimpleNamespace(stdout=request), SimpleNamespace(stdout=result)]) as run:
                watcher.main()
            saved = root / 'attempt' / 'request.event.json'
            self.assertEqual(saved.read_bytes(), request)
            self.assertEqual(saved.stat().st_mode & 0o777, 0o444)
            self.assertEqual((root / 'ack.json').read_bytes(), result)
            self.assertEqual(run.call_args_list[0].args[0][7], 'await-request')
            self.assertEqual(run.call_args_list[1].args[0][7], 'begin')
            self.assertEqual(run.call_args_list[0].kwargs['timeout'], 32)
            chown.assert_called_once_with(root / 'stores' / ('ab' * 32), 1201, 1201)

    def test_unprivileged_capture_fails_before_any_network_or_write(self):
        with patch.object(watcher.os, 'geteuid', return_value=1000), patch.object(watcher.subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                watcher.main()
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
