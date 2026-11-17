import base64
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import config
import otp
import service

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import manage


class ServiceTests(unittest.TestCase):
    def test_backend_not_ready_when_paths_are_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(service, 'BACKEND_SOCKET', root / 'topsap.sock'), \
                    patch.object(service, 'LEGACY_BACKEND_MARKER', root / '.BUFF'):
                self.assertFalse(service.backend_ready())

    def test_backend_readiness_rejects_regular_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            socket_path = root / 'topsap.sock'
            legacy_path = root / '.BUFF'
            socket_path.touch()
            legacy_path.touch()
            with patch.object(service, 'BACKEND_SOCKET', socket_path), \
                    patch.object(service, 'LEGACY_BACKEND_MARKER', legacy_path):
                self.assertFalse(service.backend_ready())

    def test_backend_ready_when_unix_socket_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            socket_path = root / 'topsap.sock'
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(socket_path))
                with patch.object(service, 'BACKEND_SOCKET', socket_path), \
                        patch.object(service, 'LEGACY_BACKEND_MARKER', root / '.BUFF'):
                    self.assertTrue(service.backend_ready())

    def test_backend_ready_when_legacy_marker_directory_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy_path = root / '.BUFF'
            legacy_path.mkdir()
            with patch.object(service, 'BACKEND_SOCKET', root / 'topsap.sock'), \
                    patch.object(service, 'LEGACY_BACKEND_MARKER', legacy_path):
                self.assertTrue(service.backend_ready())

    def test_service_configuration_requires_socks_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.env').write_text(
                'VPN_HOST=vpn.example.com:443\nVPN_ACCOUNT=user\nVPN_PASSWD=password\n'
                'VPN_TOTP_SECRET=TESTSEED\nVPN_DNS=10.0.0.53\nHEALTHCHECK_HOST=10.0.0.10\n'
                'SOCKS_USERNAME=alice\nSOCKS_PASSWORD=secret\n')
            with patch.object(manage, 'ROOT', root), patch.dict(os.environ):
                values = manage.load()
            self.assertEqual(values['SOCKS_PORT'], 1080)
            self.assertEqual(values['HEALTHCHECK_PORT'], 443)
            self.assertEqual(values['SOCKS_USERNAME'], 'alice')
            self.assertEqual(values['SOCKS_PASSWORD'], 'secret')

    def test_socks_credentials_must_be_nonempty_nul_free_and_at_most_255_bytes(self):
        base = ('VPN_HOST=vpn.example.com:443\nVPN_ACCOUNT=user\nVPN_PASSWD=password\n'
                'VPN_TOTP_SECRET=TESTSEED\nVPN_DNS=10.0.0.53\nHEALTHCHECK_HOST=10.0.0.10\n')
        invalid = (
            ('SOCKS_USERNAME', None, 'secret'),
            ('SOCKS_PASSWORD', 'alice', None),
            ('SOCKS_USERNAME', '', 'secret'),
            ('SOCKS_PASSWORD', 'alice', ''),
            ('SOCKS_USERNAME', 'bad\0name', 'secret'),
            ('SOCKS_PASSWORD', 'alice', 'bad\0secret'),
            ('SOCKS_USERNAME', 'u' * 256, 'secret'),
            ('SOCKS_PASSWORD', 'alice', 'é' * 128),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.env'
            for changed, username, password in invalid:
                with self.subTest(changed=changed, username=username, password=password):
                    lines = base
                    if username is not None:
                        lines += f"SOCKS_USERNAME='{username}'\n"
                    if password is not None:
                        lines += f"SOCKS_PASSWORD='{password}'\n"
                    path.write_text(lines)
                    with patch.dict(os.environ, {'TOPSAP_ENV_FILE': str(path)}):
                        with self.assertRaises(ValueError) as caught:
                            config.settings()
                    self.assertNotIn('bad', str(caught.exception))

    def test_run_cycle_configures_required_authentication_and_probes_with_credentials(self):
        config_values = {
            'HEALTHCHECK_HOST': '10.0.0.10',
            'HEALTHCHECK_PORT': 443,
            'VPN_HOST': 'vpn.example.com:443',
            'VPN_DNS': '10.0.0.53',
            'LOGIN_TIMEOUT': 30,
            'DEBUG_DESKTOP': '0',
            'SOCKS_USERNAME': 'alice',
            'SOCKS_PASSWORD': 'secret',
        }
        launched = []
        probed = []
        pipes = []

        class Pipe:
            def __init__(self):
                self.data = bytearray()
                self.closed = False

            def write(self, data):
                self.data.extend(data)
                return len(data)

            def close(self):
                self.closed = True

        class Process:
            def __init__(self, args):
                self.args = args
                self.pid = len(launched) + 100
                self.returncode = 0 if args[-1].endswith('vpn_login.py') else None
                self.stdin = Pipe()
                pipes.append(self.stdin)

            def poll(self):
                return self.returncode

        def launch(args, **kwargs):
            launched.append((args, kwargs))
            return Process(args)

        def sleep(seconds):
            if seconds == 10:
                service.STOPPING = True

        service.STOPPING = False
        try:
            with patch.object(service, 'status'), \
                    patch.object(service, 'prepare'), \
                    patch.object(service, 'gateway_firewall'), \
                    patch.object(service, 'launch', side_effect=launch), \
                    patch.object(service, 'backend_ready', return_value=True), \
                    patch.object(service.pathlib.Path, 'exists', return_value=True), \
                    patch.object(service, 'wait_until', side_effect=lambda predicate, *_: self.assertTrue(predicate())), \
                    patch.object(service, 'tunnel_for', return_value='tun0'), \
                    patch.object(service, 'vpn_resolver'), \
                    patch.object(service, 'probe', side_effect=lambda *args, **kwargs: probed.append((args, kwargs))), \
                    patch.object(service, 'terminate'), \
                    patch.object(service, 'command', return_value='[]'), \
                    patch.object(service, 'sleep', side_effect=sleep), \
                    patch.object(service, 'log'):
                service.run_cycle(config_values, 'nameserver 127.0.0.11\n', lambda: None)
        finally:
            service.STOPPING = False

        proxy_args = next(args for args, _ in launched if args[0] == 'setpriv')
        self.assertEqual(proxy_args[-5:], ['microsocks', '-i', '127.0.0.1', '-p', '1081'])
        auth_proxy_args = next(args for args, _ in launched if args[-1].endswith('auth_proxy.py'))
        self.assertEqual(auth_proxy_args[-2:], [sys.executable, str(service.PROGRAMS / 'auth_proxy.py')])
        self.assertEqual(auth_proxy_args[:5], ['setpriv', '--reuid=65534', '--regid=65534',
                                               '--clear-groups', '--no-new-privs'])
        self.assertNotIn('alice', repr(launched))
        self.assertNotIn('secret', repr(launched))
        auth_pipe = pipes[-1]
        self.assertTrue(auth_pipe.closed)
        self.assertEqual(json.loads(auth_pipe.data), ['alice', 'secret'])
        self.assertEqual(len(probed), 2)
        self.assertTrue(all(kwargs == {'username': 'alice', 'password': 'secret'}
                            for _, kwargs in probed))

    def test_start_auth_proxy_reaps_child_when_stdin_write_fails(self):
        class BrokenPipe:
            def __init__(self):
                self.closed = False

            def write(self, payload):
                raise BrokenPipeError('closed pipe')

            def close(self):
                self.closed = True

        class Process:
            pid = 321

            def __init__(self):
                self.stdin = BrokenPipe()

        process = Process()
        terminated = []
        with patch.object(service, 'launch', return_value=process), \
                patch.object(service, 'terminate', side_effect=lambda processes: terminated.append(processes)):
            with self.assertRaisesRegex(BrokenPipeError, 'closed pipe'):
                service.start_auth_proxy({'SOCKS_USERNAME': 'alice', 'SOCKS_PASSWORD': 'secret'}, {})
        self.assertTrue(process.stdin.closed)
        self.assertEqual(terminated, [[process]])

    def test_rfc6238_sha1_vectors(self):
        seed = base64.b32encode(b'12345678901234567890').decode()
        vectors = [(59, '94287082'), (1111111109, '07081804'),
                   (1111111111, '14050471'), (1234567890, '89005924'),
                   (2000000000, '69279037'), (20000000000, '65353130')]
        for timestamp, token in vectors:
            self.assertEqual(otp.totp(seed, timestamp, digits=8), token)

    def test_env_is_data_and_does_not_expand_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env'
            path.write_text("PASSWORD='literal # $HOME $(touch should-not-exist)'\n")
            self.assertEqual(config.read_env(path)['PASSWORD'],
                             'literal # $HOME $(touch should-not-exist)')
            path.write_text('A=one\nA=two\n')
            with self.assertRaises(ValueError):
                config.read_env(path)

    def test_login_limit_including_slow_failures_and_success_reset(self):
        for reset_case in (False, True):
            with self.subTest(reset_case=reset_case):
                service.STOPPING = False
                attempts, states = [], []
                clock = [0]
                def cycle(settings, resolver, on_ready):
                    attempts.append(1)
                    clock[0] += 400
                    if reset_case and len(attempts) == 2:
                        on_ready()
                        raise RuntimeError()
                    raise service.AuthenticationError()
                def sleep(seconds):
                    if states[-1] == 'needs_attention':
                        service.STOPPING = True
                with patch.object(service, 'settings', return_value={'LOGIN_FAILURE_LIMIT': 3}), \
                     patch.object(service.pathlib.Path, 'mkdir'), \
                     patch.object(service.pathlib.Path, 'chmod'), \
                     patch.object(service.pathlib.Path, 'exists', return_value=True), \
                     patch.object(service, 'install_firewall'), \
                     patch.object(service, 'run_cycle', side_effect=cycle), \
                     patch.object(service, 'status', side_effect=lambda state, **kw: states.append(state)), \
                     patch.object(service, 'sleep', side_effect=sleep), \
                     patch.object(service, 'log'), \
                     patch.object(service.time, 'monotonic', side_effect=lambda: clock[0]):
                    service.main()
                self.assertEqual(len(attempts), 5 if reset_case else 3)
                self.assertIn('needs_attention', states)
        service.STOPPING = False
