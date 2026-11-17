import contextlib
import io
import os
from pathlib import Path
import select
import socket
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'app'))
import socks_connect as client


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError('unexpected EOF in test server')
        data.extend(part)
    return bytes(data)


def socks_request(sock):
    version, count = exact(sock, 2)
    methods = exact(sock, count)
    if version != 5 or methods != b'\x02':
        raise AssertionError('client did not require username/password auth')
    sock.sendall(b'\x05\x02')
    version, user_size = exact(sock, 2)
    username = exact(sock, user_size)
    password_size = exact(sock, 1)[0]
    password = exact(sock, password_size)
    if version != 1:
        raise AssertionError('invalid username/password subnegotiation')
    sock.sendall(b'\x01\x00')

    version, command, reserved, atyp = exact(sock, 4)
    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, exact(sock, 4))
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, exact(sock, 16))
    elif atyp == 3:
        host = exact(sock, exact(sock, 1)[0]).decode('idna')
    else:
        raise AssertionError('invalid SOCKS address type')
    port = struct.unpack('>H', exact(sock, 2))[0]
    if (version, command, reserved) != (5, 1, 0):
        raise AssertionError('invalid SOCKS connect request')
    return username, password, host, port


class SocksClientTests(unittest.TestCase):
    def credentials(self, directory, mode=0o600):
        path = Path(directory) / 'credentials'
        path.write_text('SOCKS_USERNAME="test user"\nSOCKS_PASSWORD="secret-value"\n')
        path.chmod(mode)
        return path

    def test_private_credentials_and_local_echo_with_half_close(self):
        payload = bytes(range(256)) * 2048 + b'\x00binary\xff'
        server_errors = []
        received = {}
        with tempfile.TemporaryDirectory() as directory:
            credentials = self.credentials(directory)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                listener.settimeout(5)
                proxy_port = listener.getsockname()[1]

                def serve():
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(10)
                            received.update(zip(
                                ('username', 'password', 'host', 'port'),
                                socks_request(connection)))
                            connection.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50')
                            chunks = bytearray()
                            while True:
                                block = connection.recv(4096)
                                if not block:
                                    break
                                chunks.extend(block)
                            received['payload'] = bytes(chunks)
                            connection.sendall(chunks)
                            connection.shutdown(socket.SHUT_WR)
                    except Exception as error:
                        server_errors.append(error)

                server = threading.Thread(target=serve, daemon=True)
                server.start()
                input_read, input_write = os.pipe()
                output_read, output_write = os.pipe()
                try:
                    stderr = io.StringIO()
                    results = []
                    with contextlib.redirect_stderr(stderr):
                        runner = threading.Thread(target=lambda: results.append(client.main([
                            '--credentials', str(credentials),
                            '--proxy-port', str(proxy_port),
                            'service.example', '443',
                        ], input_read, output_write)))
                        runner.start()
                        view = memoryview(payload)
                        while view:
                            count = os.write(input_write, view[:16384])
                            view = view[count:]
                        os.close(input_write)
                        input_write = -1

                        output = bytearray()
                        while runner.is_alive():
                            ready, _, _ = select.select([output_read], [], [], 0.1)
                            if ready:
                                block = os.read(output_read, 16384)
                                if block:
                                    output.extend(block)
                        runner.join(timeout=5)
                        self.assertFalse(runner.is_alive(), 'helper did not finish')
                    os.close(output_write)
                    output_write = -1
                    while True:
                        block = os.read(output_read, 4096)
                        if not block:
                            break
                        output.extend(block)
                    result = results[0]
                finally:
                    for fd in (input_read, output_read, output_write):
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                    if input_write >= 0:
                        os.close(input_write)
                server.join(timeout=5)

        self.assertFalse(server.is_alive(), 'SOCKS fixture did not finish')
        self.assertEqual(server_errors, [])
        self.assertEqual(result, 0)
        self.assertEqual(received, {
            'username': b'test user', 'password': b'secret-value',
            'host': 'service.example', 'port': 443, 'payload': payload,
        })
        self.assertEqual(bytes(output), payload)
        self.assertNotIn('secret-value', stderr.getvalue())
        self.assertEqual(stderr.getvalue(), '')

    def test_insecure_permissions_are_rejected_without_echoing_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            credentials = self.credentials(directory, 0o640)
            stderr = io.StringIO()
            stdout = io.BytesIO()
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                result = client.main([
                    '--credentials', str(credentials),
                    'service.example', '443',
                ])
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), b'')
        self.assertEqual(stderr.getvalue(), 'socks-connect: connection failed\n')
        self.assertNotIn('secret-value', stderr.getvalue())

    def test_credentials_must_be_owned_by_current_user(self):
        with tempfile.TemporaryDirectory() as directory:
            credentials = self.credentials(directory)
            with patch.object(client.os, 'getuid', return_value=os.getuid() + 1):
                with self.assertRaises(ValueError):
                    client.read_credentials(credentials)

    def test_authentication_failure_is_generic_and_does_not_leak_secret(self):
        errors = []
        with tempfile.TemporaryDirectory() as directory:
            credentials = self.credentials(directory)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                listener.settimeout(5)
                port = listener.getsockname()[1]

                def reject():
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(5)
                            version, count = exact(connection, 2)
                            methods = exact(connection, count)
                            if (version, methods) != (5, b'\x02'):
                                raise AssertionError('unexpected auth methods')
                            connection.sendall(b'\x05\xff')
                    except Exception as error:
                        errors.append(error)

                server = threading.Thread(target=reject, daemon=True)
                server.start()
                stderr = io.StringIO()
                stdout = io.StringIO()
                with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                    result = client.main([
                        '--credentials', str(credentials), '--proxy-port', str(port),
                        'service.example', '443',
                    ])
                server.join(timeout=5)
        self.assertFalse(server.is_alive(), 'SOCKS fixture did not finish')
        self.assertEqual(errors, [])
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(stderr.getvalue(), 'socks-connect: connection failed\n')
        self.assertNotIn('secret-value', stderr.getvalue())

    def test_ssh_command_disables_multiplexing_and_contains_no_credentials(self):
        command = client.ssh_command('proxy-host', '2001:db8::5', 1080)
        self.assertEqual(command[:2], ['ssh', '-T'])
        self.assertIn('ControlMaster=no', command)
        self.assertIn('ControlPath=none', command)
        self.assertIn('ControlPersist=no', command)
        self.assertEqual(command[-3:], ['-W', '[2001:db8::5]:1080', 'proxy-host'])
        self.assertNotIn('secret-value', ' '.join(command))

    def test_ssh_tunnel_auth_failure_closes_and_reaps_child(self):
        server_errors = []
        with tempfile.TemporaryDirectory() as directory:
            credentials = self.credentials(directory)
            process_end, server_end = socket.socketpair()
            with contextlib.closing(process_end), contextlib.closing(server_end):
                class FakeProcess:
                    def __init__(self):
                        self.stdin = process_end.makefile('wb', buffering=0)
                        self.stdout = process_end.makefile('rb', buffering=0)
                        self.returncode = None
                        self.wait_calls = 0

                    def wait(self, timeout=None):
                        self.wait_calls += 1
                        self.returncode = 0
                        return 0

                process = FakeProcess()

                def reject():
                    try:
                        server_end.settimeout(5)
                        version, count = exact(server_end, 2)
                        methods = exact(server_end, count)
                        if (version, methods) != (5, b'\x02'):
                            raise AssertionError('unexpected auth methods')
                        server_end.sendall(b'\x05\xff')
                    except Exception as error:
                        server_errors.append(error)

                server = threading.Thread(target=reject, daemon=True)
                server.start()
                stderr = io.StringIO()
                with patch.object(client.subprocess, 'Popen', return_value=process) as popen:
                    with contextlib.redirect_stderr(stderr):
                        result = client.main([
                            '--credentials', str(credentials), '--ssh', 'proxy-host',
                            '--proxy-host', 'proxy.internal', '--proxy-port', '1080',
                            'service.example', '443',
                        ])
                server.join(timeout=5)
                process_end.close()
                self.assertFalse(server.is_alive(), 'SSH fixture did not finish')

        self.assertEqual(server_errors, [])
        self.assertEqual(result, 1)
        self.assertEqual(process.wait_calls, 1)
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertEqual(stderr.getvalue(), 'socks-connect: connection failed\n')
        self.assertNotIn('secret-value', stderr.getvalue())
        command, = popen.call_args.args
        self.assertIn('ControlMaster=no', command)
        self.assertIn('ControlPath=none', command)
        self.assertIn('ControlPersist=no', command)
        self.assertNotIn('secret-value', ' '.join(command))

    def test_remote_half_close_keeps_upload_direction(self):
        payload = bytes(range(256)) * 16 + b'after-remote-eof'
        received = {}
        server_errors = []
        ready = threading.Event()
        with tempfile.TemporaryDirectory() as directory:
            credentials = self.credentials(directory)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                proxy_port = listener.getsockname()[1]

                def serve():
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(5)
                            socks_request(connection)
                            connection.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50')
                            connection.shutdown(socket.SHUT_WR)
                            ready.set()
                            chunks = bytearray()
                            while True:
                                block = connection.recv(4096)
                                if not block:
                                    break
                                chunks.extend(block)
                            received['payload'] = bytes(chunks)
                    except Exception as error:
                        server_errors.append(error)
                        ready.set()

                server = threading.Thread(target=serve, daemon=True)
                server.start()
                input_read, input_write = os.pipe()
                output_read, output_write = os.pipe()
                try:
                    os.write(input_write, payload)
                    os.close(input_write)
                    input_write = -1
                    results = []
                    stderr = io.StringIO()
                    with contextlib.redirect_stderr(stderr):
                        runner = threading.Thread(target=lambda: results.append(client.main([
                            '--credentials', str(credentials),
                            '--proxy-port', str(proxy_port),
                            'service.example', '443',
                        ], input_read, output_write)))
                        runner.start()
                        self.assertTrue(ready.wait(5), 'SOCKS fixture did not send remote EOF')
                        runner.join(timeout=5)
                        self.assertFalse(runner.is_alive(), 'helper did not finish')
                        result = results[0]
                    os.close(output_write)
                    output_write = -1
                    output = os.read(output_read, 4096)
                finally:
                    for fd in (input_read, output_read, output_write):
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                    if input_write >= 0:
                        os.close(input_write)
                server.join(timeout=5)

        self.assertFalse(server.is_alive(), 'SOCKS fixture did not finish')
        self.assertEqual(server_errors, [])
        self.assertEqual(result, 0)
        self.assertEqual(received.get('payload'), payload)
        self.assertEqual(output, b'')
        self.assertEqual(stderr.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
