import contextlib
import io
import os
from pathlib import Path
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'app'))
sys.path.insert(0, str(ROOT / 'tests'))
import socks_connect as client
from tls_helpers import temporary_tls_certificates


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError('unexpected EOF in test server')
        data.extend(part)
    return bytes(data)


def _read_all(fd, output):
    while True:
        data = os.read(fd, 65536)
        if not data:
            return
        output.extend(data)


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

    def tls_server_context(self, fixture):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(fixture.cert_path), str(fixture.key_path))
        return context

    def start_tls_server(self, listener, context, handler, errors,
                         *, expected_tls_failure=False, accepted=None):
        def serve():
            try:
                connection, _ = listener.accept()
                if accepted is not None:
                    accepted.set()
                with connection:
                    connection.settimeout(5)
                    with context.wrap_socket(connection, server_side=True) as secure:
                        handler(secure)
            except Exception as error:
                expected_errors = (ssl.SSLError, ConnectionAbortedError,
                                   ConnectionResetError, BrokenPipeError, TimeoutError)
                if not (expected_tls_failure and isinstance(error, expected_errors)):
                    errors.append(error)

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        return server

    def test_tls_echo_verifies_proxy_certificate_and_relays_bounded_binary_data(self):
        payload = bytes(range(256)) * 768 + b'\x00tls-binary\xff'
        received = {}
        server_errors = []
        with tempfile.TemporaryDirectory() as directory, \
                temporary_tls_certificates() as fixture:
            credentials = self.credentials(directory)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                listener.settimeout(5)
                port = listener.getsockname()[1]

                def serve(secure):
                    received['credentials'] = socks_request(secure)
                    secure.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50')
                    received['payload'] = exact(secure, len(payload))
                    secure.sendall(received['payload'])

                server = self.start_tls_server(
                    listener, self.tls_server_context(fixture), serve, server_errors)
                input_read, input_write = os.pipe()
                output_read, output_write = os.pipe()
                output = bytearray()
                reader = threading.Thread(
                    target=lambda: _read_all(output_read, output), daemon=True)
                results = []
                stderr = io.StringIO()
                argv = [
                    '--credentials', str(credentials), '--proxy-port', str(port),
                    '--tls', '--tls-ca', str(fixture.cert_path),
                    '--tls-server-name', 'localhost',
                    'service.example', '443',
                ]
                try:
                    reader.start()
                    with contextlib.redirect_stderr(stderr):
                        runner = threading.Thread(
                            target=lambda: results.append(client.main(
                                argv, input_read, output_write)))
                        runner.start()
                        view = memoryview(payload)
                        while view:
                            count = os.write(input_write, view[:16384])
                            view = view[count:]
                        server.join(timeout=5)
                        self.assertFalse(server.is_alive(), 'TLS server did not finish')
                        runner.join(timeout=5)
                        self.assertFalse(runner.is_alive(), 'TLS relay did not finish after peer close')
                    os.close(output_write)
                    output_write = -1
                    reader.join(timeout=5)
                finally:
                    for fd in (input_read, output_read, output_write):
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                    try:
                        os.close(input_write)
                    except OSError:
                        pass

        self.assertFalse(reader.is_alive(), 'TLS output reader did not finish')
        self.assertEqual(server_errors, [])
        self.assertEqual(received['credentials'],
                         (b'test user', b'secret-value', 'service.example', 443))
        self.assertEqual(received['payload'], payload)
        self.assertEqual(results, [0])
        self.assertEqual(bytes(output), payload)
        self.assertEqual(stderr.getvalue(), '')
        self.assertEqual(client.tls_context().minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_tls_rejects_untrusted_and_mismatched_certificates_before_socks_auth(self):
        with tempfile.TemporaryDirectory() as directory, \
                temporary_tls_certificates() as fixture:
            credentials = self.credentials(directory)
            for extra_args in ([], [
                    '--tls-ca', str(fixture.cert_path),
                    '--tls-server-name', 'wrong.example']):
                with self.subTest(extra_args=extra_args):
                    server_errors = []
                    application_data = bytearray()
                    accepted = threading.Event()
                    with socket.socket() as listener:
                        listener.bind(('127.0.0.1', 0))
                        listener.listen(1)
                        listener.settimeout(5)
                        port = listener.getsockname()[1]

                        def inspect_client(secure):
                            try:
                                secure.settimeout(0.5)
                                while data := secure.recv(4096):
                                    application_data.extend(data)
                            except (ssl.SSLError, TimeoutError):
                                pass

                        server = self.start_tls_server(
                            listener, self.tls_server_context(fixture), inspect_client,
                            server_errors, expected_tls_failure=True, accepted=accepted)
                        stderr = io.StringIO()
                        stdin_read, stdin_write = os.pipe()
                        stdout_read, stdout_write = os.pipe()
                        original_run = client.run
                        run_errors = []

                        def capture_run_error(*args, **kwargs):
                            try:
                                return original_run(*args, **kwargs)
                            except Exception as error:
                                run_errors.append(error)
                                raise

                        try:
                            with contextlib.redirect_stderr(stderr), \
                                    patch.object(client, 'run', side_effect=capture_run_error):
                                result = client.main([
                                    '--credentials', str(credentials), '--proxy-port', str(port),
                                    '--tls', *extra_args, 'service.example', '443',
                                ], stdin_read, stdout_write)
                            os.close(stdout_write)
                            stdout_write = -1
                            stdout = bytearray()
                            while data := os.read(stdout_read, 4096):
                                stdout.extend(data)
                        finally:
                            for fd in (stdin_read, stdin_write, stdout_read, stdout_write):
                                try:
                                    os.close(fd)
                                except OSError:
                                    pass
                        server.join(timeout=5)

                    self.assertFalse(server.is_alive(), 'TLS rejection fixture did not finish')
                    self.assertTrue(
                        accepted.is_set(),
                        f'TLS client did not reach certificate check: {run_errors!r}')
                    self.assertEqual(result, 1)
                    self.assertEqual(len(run_errors), 1)
                    self.assertIsInstance(run_errors[0], ssl.SSLCertVerificationError)
                    self.assertEqual(bytes(stdout), b'')
                    self.assertEqual(stderr.getvalue(), 'socks-connect: connection failed\n')
                    self.assertEqual(bytes(application_data), b'')
                    self.assertEqual(server_errors, [])

    def test_tls_options_are_rejected_without_tls_or_with_ssh(self):
        with tempfile.TemporaryDirectory() as directory:
            credentials = self.credentials(directory)
            for options in (
                    ['--tls-ca', str(Path(directory) / 'ca.pem')],
                    ['--tls-server-name', 'localhost'],
                    ['--tls', '--ssh', 'proxy-host']):
                with self.subTest(options=options):
                    stderr = io.StringIO()
                    with contextlib.redirect_stderr(stderr):
                        result = client.main([
                            '--credentials', str(credentials), *options,
                            'service.example', '443',
                        ])
                    self.assertEqual(result, 1)
                    self.assertEqual(stderr.getvalue(), 'socks-connect: connection failed\n')

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

    def test_proxycommand_termination_is_quiet_and_reaps_ssh_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            credentials = self.credentials(directory)
            ready, stopped = root / 'ready', root / 'stopped'
            ssh = root / 'ssh'
            ssh.write_text(f'#!{sys.executable}\n' + '''import os, sys
from pathlib import Path
def exact(size):
    data = sys.stdin.buffer.read(size)
    if len(data) != size:
        raise SystemExit(2)
    return data
def reply(data):
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
assert exact(3) == b'\\x05\\x01\\x02'
reply(b'\\x05\\x02')
version, size = exact(2)
assert version == 1
exact(size)
exact(exact(1)[0])
reply(b'\\x01\\x00')
assert exact(4) == b'\\x05\\x01\\x00\\x03'
exact(exact(1)[0] + 2)
reply(b'\\x05\\x00\\x00\\x01\\x7f\\x00\\x00\\x01\\x00\\x50')
''' + f'Path({str(ready)!r}).write_text(str(os.getpid()))\n'
                + 'sys.stdin.buffer.read()\n'
                + f'Path({str(stopped)!r}).touch()\n')
            ssh.chmod(0o700)
            process = subprocess.Popen(
                [sys.executable, str(ROOT / 'scripts' / 'socks_connect.py'),
                 '--credentials', str(credentials), '--ssh', 'proxy-host',
                 'service.example', '443'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                         PYTHONDONTWRITEBYTECODE='1'), start_new_session=True)
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), 'SSH fixture did not reach the relay phase')
                child_pid = int(ready.read_text())
                process.terminate()
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 128 + signal.SIGTERM)
                self.assertEqual(stdout, b'')
                self.assertEqual(stderr, b'')
                self.assertTrue(stopped.exists(), 'SSH child did not receive EOF during cleanup')
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)
            finally:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)

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
