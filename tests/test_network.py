from concurrent.futures import ThreadPoolExecutor
import ipaddress
from pathlib import Path
import socket
import ssl
import struct
import sys
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import network


class SocksConnectTests(unittest.TestCase):
    def test_tls_probe_verifies_certificate_before_sending_credentials(self):
        transport = MagicMock()
        context = Mock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError('untrusted fixture')
        with patch.object(network.socket, 'create_connection', return_value=transport), \
                patch.object(network.ssl, 'create_default_context', return_value=context) as factory, \
                patch.object(network, 'socks_connect') as connect:
            with self.assertRaises(ssl.SSLCertVerificationError):
                network.probe('10.0.0.10', 22, username='alice', password='secret',
                              tls_ca='/test/cert.pem', tls_server_name='proxy.example.com')
        factory.assert_called_once_with(cafile='/test/cert.pem')
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.wrap_socket.call_args.kwargs['server_hostname'], 'proxy.example.com')
        connect.assert_not_called()

    def test_tls_probe_options_preserve_plain_loopback_mode(self):
        self.assertEqual(network.tls_probe_options({}), {})
        self.assertEqual(network.tls_probe_options({'SOCKS_TLS': '1',
                                                   'SOCKS_TLS_SERVER_NAME': 'proxy.example.com'}),
                         {'tls_ca': '/run/secrets/socks-tls.crt',
                          'tls_server_name': 'proxy.example.com'})

    def test_destination_port_must_be_nonzero(self):
        class Socket:
            def sendall(self, data):
                pass

            def recv(self, size):
                return b'\x05\x00'[:size]

        with self.assertRaisesRegex(ValueError, 'destination port'):
            network.socks_connect(Socket(), '127.0.0.1', 0)

    def exchange(self, host, port, *, username=None, password=None,
                 greeting=None, auth_reply=b'\x01\x00',
                 connect_reply=b'\x05\x00\x00\x01' + b'\x00' * 6):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(5)

            def proxy():
                with listener.accept()[0] as connection:
                    connection.settimeout(5)
                    version, count = network.exact(connection, 2)
                    methods = network.exact(connection, count)
                    expected_method = 0x02 if username is not None else 0x00
                    selected_greeting = greeting or bytes([5, expected_method])
                    self.assertEqual(version, 5)
                    self.assertEqual(methods, bytes([expected_method]))
                    connection.sendall(selected_greeting)
                    if (len(selected_greeting) != 2 or selected_greeting[0] != 5
                            or selected_greeting[1] != expected_method):
                        return
                    if expected_method == 2:
                        auth_version, user_size = network.exact(connection, 2)
                        user = network.exact(connection, user_size)
                        password_size = network.exact(connection, 1)[0]
                        password_bytes = network.exact(connection, password_size)
                        self.assertEqual(auth_version, 1)
                        self.assertEqual(user, username.encode('utf-8'))
                        self.assertEqual(password_bytes, password.encode('utf-8'))
                        connection.sendall(auth_reply)
                        if auth_reply != b'\x01\x00':
                            return

                    request_header = network.exact(connection, 4)
                    self.assertEqual(request_header[:3], b'\x05\x01\x00')
                    if request_header[3] == 1:
                        destination = network.exact(connection, 4)
                    elif request_header[3] == 4:
                        destination = network.exact(connection, 16)
                    elif request_header[3] == 3:
                        size = network.exact(connection, 1)[0]
                        destination = bytes([size]) + network.exact(connection, size)
                    else:
                        self.fail('Unexpected SOCKS destination address type')
                    destination_port = network.exact(connection, 2)
                    try:
                        address = ipaddress.ip_address(host)
                    except ValueError:
                        expected_host = host.encode('idna')
                        expected_atyp = 3
                        expected_address = bytes([len(expected_host)]) + expected_host
                    else:
                        expected_atyp = 1 if address.version == 4 else 4
                        expected_address = address.packed
                    self.assertEqual(request_header[3], expected_atyp)
                    self.assertEqual(destination, expected_address)
                    self.assertEqual(struct.unpack('>H', destination_port)[0], port)
                    connection.sendall(connect_reply)

            with ThreadPoolExecutor(max_workers=1) as executor:
                result = executor.submit(proxy)
                error = None
                try:
                    network.probe(host, port, proxy_port=listener.getsockname()[1],
                                  username=username, password=password)
                except Exception as caught:
                    error = caught
                result.result(timeout=6)
                return error

    def test_success_for_ip_and_idna_targets_with_and_without_authentication(self):
        for host, port, username, password in (
                ('10.0.0.10', 22, None, None),
                ('10.0.0.10', 443, 'alice', 'pāssword'),
                ('fd00::10', 8443, 'alice', 'secret'),
                ('bücher.example', 443, 'alice', 'secret')):
            with self.subTest(host=host, port=port):
                self.assertIsNone(self.exchange(host, port, username=username, password=password))

    def test_authentication_rejection_and_downgrade_are_errors(self):
        rejected = self.exchange('vpn.example', 443, username='alice', password='secret',
                                 auth_reply=b'\x01\x01')
        self.assertIsInstance(rejected, ConnectionError)
        self.assertIn('authentication failed', str(rejected))

        downgraded = self.exchange('vpn.example', 443, username='alice', password='secret',
                                   greeting=b'\x05\x00')
        self.assertIsInstance(downgraded, ConnectionError)
        self.assertIn('negotiation failed', str(downgraded))

        unsupported = self.exchange('vpn.example', 443, greeting=b'\x05\x02')
        self.assertIsInstance(unsupported, ConnectionError)
        self.assertIn('negotiation failed', str(unsupported))

        bad_auth_version = self.exchange('vpn.example', 443, username='alice', password='secret',
                                         auth_reply=b'\x02\x00')
        self.assertIsInstance(bad_auth_version, ConnectionError)
        self.assertIn('authentication failed', str(bad_auth_version))

    def test_invalid_connect_reply_fields_and_destination_status_are_errors(self):
        cases = (
            (b'\x04\x00\x00\x01' + b'\x00' * 6, 'reply version'),
            (b'\x05\x00\x01\x01' + b'\x00' * 6, 'reserved field'),
            (b'\x05\x05\x00\x01' + b'\x00' * 6, 'destination connection failed'),
            (b'\x05\x00\x00\x05' + b'\x00' * 6, 'address type'),
            (b'\x05\x00\x00\x03\x00' + b'\x00' * 2, 'address'),
        )
        for reply, message in cases:
            with self.subTest(reply=reply):
                error = self.exchange('10.0.0.10', 443, username='alice', password='secret',
                                      connect_reply=reply)
                self.assertIsInstance(error, ConnectionError)
                self.assertIn(message, str(error))

    def test_proxy_firewall_allows_only_the_internal_auth_backend_route(self):
        calls = []

        def command(*args):
            calls.append(args)
            if args == ('ip', '-j', 'route', 'show', 'default'):
                return '[{"gateway":"192.0.2.1"}]'
            return ''

        completed = Mock(returncode=0)
        with patch.object(network, 'command', side_effect=command), \
                patch.object(network.subprocess, 'run', return_value=completed):
            network.install_firewall()

        self.assertIn(('iptables', '-w', '-A', 'TOPSAP_PROXY', '-o', 'lo', '-d',
                       '127.0.0.1', '-p', 'tcp', '--dport', '1081', '-j', 'ACCEPT'), calls)
        self.assertNotIn(('ip6tables', '-w', '-A', 'TOPSAP_PROXY', '-o', 'lo', '-d',
                          '127.0.0.1', '-p', 'tcp', '--dport', '1081', '-j', 'ACCEPT'), calls)
        self.assertIn(('iptables', '-w', '-A', 'TOPSAP_INPUT', '-j', 'REJECT'), calls)

    def test_tls_frontend_accepts_external_clients_without_opening_backend(self):
        calls = []

        def command(*args):
            calls.append(args)
            if args == ('ip', '-j', 'route', 'show', 'default'):
                return '[{"gateway":"192.0.2.1"}]'
            return ''

        with patch.object(network, 'command', side_effect=command), \
                patch.object(network.subprocess, 'run', return_value=Mock(returncode=1)):
            network.install_firewall(tls=True)
        for tool in ('iptables', 'ip6tables'):
            self.assertIn((tool, '-w', '-A', 'TOPSAP_INPUT', '-j', 'ACCEPT'), calls)
            self.assertIn((tool, '-w', '-I', 'INPUT', '-p', 'tcp', '--dport', '1080',
                           '-j', 'TOPSAP_INPUT'), calls)
        self.assertNotIn(('iptables', '-w', '-A', 'TOPSAP_PROXY', '-o', 'eth0', '-j', 'ACCEPT'), calls)


if __name__ == '__main__':
    unittest.main()
