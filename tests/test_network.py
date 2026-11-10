from concurrent.futures import ThreadPoolExecutor
import ipaddress
from pathlib import Path
import socket
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import network


class ProbeTests(unittest.TestCase):
    def exchange(self, host, port, reply_code=0):
        address = ipaddress.ip_address(host)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(5)

            def proxy():
                with listener.accept()[0] as connection:
                    connection.settimeout(5)
                    self.assertEqual(network.exact(connection, 3), b'\x05\x01\x00')
                    connection.sendall(b'\x05\x00')
                    request = network.exact(connection, 4 + len(address.packed) + 2)
                    expected = (b'\x05\x01\x00' + bytes([1 if address.version == 4 else 4])
                                + address.packed + struct.pack('>H', port))
                    self.assertEqual(request, expected)
                    connection.sendall(bytes([5, reply_code, 0, 1]) + b'\x00' * 6)
                    # TCP connection succeeded; no application banner is sent.

            with ThreadPoolExecutor(max_workers=1) as executor:
                result = executor.submit(proxy)
                try:
                    network.probe(host, port, proxy_port=listener.getsockname()[1])
                finally:
                    result.result(timeout=6)

    def test_tcp_success_does_not_require_an_application_banner(self):
        for host, port in [('10.0.0.10', 22), ('10.0.0.10', 443), ('fd00::10', 8443)]:
            with self.subTest(host=host, port=port):
                self.exchange(host, port)

    def test_destination_connection_failure_is_unhealthy(self):
        with self.assertRaisesRegex(ConnectionError, 'destination connection failed'):
            self.exchange('10.0.0.10', 443, reply_code=5)
