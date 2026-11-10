import base64
import os
from pathlib import Path
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
    def test_service_configuration_requires_only_vpn_and_proxy_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.env').write_text(
                'VPN_HOST=vpn.example.com:443\nVPN_ACCOUNT=user\nVPN_PASSWD=password\n'
                'VPN_TOTP_SECRET=TESTSEED\nVPN_DNS=10.0.0.53\nHEALTHCHECK_HOST=10.0.0.10\n')
            with patch.object(manage, 'ROOT', root), patch.dict(os.environ):
                values = manage.load()
            self.assertEqual(values['SOCKS_PORT'], 1080)
            self.assertEqual(values['HEALTHCHECK_PORT'], 443)

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
