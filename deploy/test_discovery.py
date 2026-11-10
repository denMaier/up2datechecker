import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest import mock

os.environ.setdefault('UP2DATE_URL', 'https://example.test')
os.environ.setdefault('UP2DATE_ENROLLMENT_SECRET', 'test-secret')
spec = importlib.util.spec_from_file_location('discover', pathlib.Path(__file__).with_name('up2date-discover.py'))
discover = importlib.util.module_from_spec(spec)
spec.loader.exec_module(discover)


class DiscoveryTests(unittest.TestCase):
    def test_partial_failures_are_logged_and_retried(self):
        items = '[{"vmid":101,"status":"running"}]'
        result = mock.Mock(stdout=items)
        hostname = mock.Mock(stdout='node\n')
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(discover, 'STATE', pathlib.Path(tmp)), mock.patch.object(discover, 'run', side_effect=[hostname, result, result]), mock.patch.object(discover, 'process', side_effect=RuntimeError('guest unavailable')):
            with self.assertLogs('up2date-discover', level='WARNING') as logs:
                self.assertEqual(discover.main(), 0)
            self.assertTrue(any('guest unavailable; will retry' in line for line in logs.output))

    def test_command_failure_reports_stderr(self):
        with mock.patch.object(discover.subprocess, 'run', return_value=mock.Mock(returncode=2, stdout='', stderr='guest agent offline')):
            with self.assertRaisesRegex(RuntimeError, 'guest agent offline'):
                discover.run(['qm'])

    def test_filters(self):
        with mock.patch.object(discover, 'INCLUDE', {'qemu/101'}), mock.patch.object(discover, 'EXCLUDE', {'blocked'}):
            self.assertTrue(discover.selected('qemu', {'vmid': 101, 'name': 'allowed'}))
            self.assertFalse(discover.selected('lxc', {'vmid': 101, 'name': 'allowed'}))
            self.assertFalse(discover.selected('qemu', {'vmid': 101, 'name': 'blocked'}))

    def test_unreachable_guest_has_no_enrollment_or_token(self):
        item = {'vmid': 101, 'status': 'running', 'name': 'test'}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(discover, 'STATE', pathlib.Path(tmp)), mock.patch.object(discover, 'INCLUDE', set()), mock.patch.object(discover, 'EXCLUDE', set()), mock.patch.object(discover, 'enroll') as enroll, mock.patch.object(discover, 'guest', side_effect=[(1, ''), (7, 'network unavailable')]):
            with self.assertRaisesRegex(RuntimeError, 'dashboard unreachable'):
                discover.process('qemu', item)
            enroll.assert_not_called()
            self.assertFalse((pathlib.Path(tmp) / 'qemu-101.token').exists())

    def test_retry_uses_same_token_and_does_not_replace_existing(self):
        item = {'vmid': 101, 'status': 'running', 'name': 'test'}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(discover, 'STATE', pathlib.Path(tmp)), mock.patch.object(discover, 'INCLUDE', set()), mock.patch.object(discover, 'EXCLUDE', set()), mock.patch.object(discover, 'enroll') as enroll, mock.patch.object(discover, 'guest', side_effect=[(1, ''), (0, ''), (1, ''), (1, ''), (0, ''), (0, '')]):
            with self.assertRaises(RuntimeError):
                discover.process('qemu', item)
            discover.process('qemu', item)
            self.assertEqual(enroll.call_args_list[0], enroll.call_args_list[1])
            self.assertEqual((pathlib.Path(tmp) / 'qemu-101.token').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
