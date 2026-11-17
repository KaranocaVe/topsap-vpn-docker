import asyncio
import contextlib
import io
import json
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
sys.path.insert(0, str(ROOT / 'tests'))
from auth_proxy import AuthProxy, _close_writer, load_tls_context, read_credentials
from tls_helpers import temporary_tls_certificates


USERNAME = 'proxy-user'
PASSWORD = 'pässword'
CONNECT_REQUEST = b'\x05\x01\x00\x03\x0bexample.com\x01\xbb'
CONNECT_REPLY = b'\x05\x00\x00\x01\x7f\x00\x00\x01\x20\xfb'


async def start_listener(handler):
    server = await asyncio.start_server(handler, '127.0.0.1', 0)
    return server, server.sockets[0].getsockname()[1]


async def read_to_eof(reader):
    data = bytearray()
    while chunk := await reader.read(4096):
        data.extend(chunk)
    return bytes(data)


async def authenticate(reader, writer, *, username=USERNAME, password=PASSWORD,
                       methods=b'\x00\x02'):
    writer.write(b'\x05' + bytes([len(methods)]) + methods)
    await writer.drain()
    method = await reader.readexactly(2)
    if method != b'\x05\x02':
        return method
    username_bytes = username.encode('utf-8')
    password_bytes = password.encode('utf-8')
    writer.write(b'\x01' + bytes([len(username_bytes)]) + username_bytes
                 + bytes([len(password_bytes)]) + password_bytes)
    await writer.drain()
    return await reader.readexactly(2)


class AuthProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.proxy = None
        self.backend = None

    async def asyncTearDown(self):
        if self.proxy is not None:
            await self.proxy.close()
        if self.backend is not None:
            self.backend.close()
            await self.backend.wait_closed()

    async def start_proxy(self, backend_port, **options):
        self.proxy = AuthProxy(
            USERNAME, PASSWORD, host='127.0.0.1', port=0,
            backend_host='127.0.0.1', backend_port=backend_port, **options)
        await self.proxy.start()
        port = self.proxy._server.sockets[0].getsockname()[1]
        return port

    async def connect(self, port):
        return await asyncio.open_connection('127.0.0.1', port)

    async def test_authenticated_binary_relay_preserves_half_close(self):
        payload = bytes(range(256)) * 5 + b'\x00binary\xff'
        received = {}
        backend_errors = []

        async def backend_handler(reader, writer):
            try:
                received['greeting'] = await reader.readexactly(3)
                writer.write(b'\x05\x00')
                await writer.drain()
                received['request'] = await reader.readexactly(len(CONNECT_REQUEST))
                writer.write(CONNECT_REPLY)
                await writer.drain()
                received['payload'] = await read_to_eof(reader)
                writer.write(b'backend:' + received['payload'])
                await writer.drain()
                writer.write_eof()
            except Exception as error:
                backend_errors.append(error)
            finally:
                writer.close()
                await writer.wait_closed()

        self.backend, backend_port = await start_listener(backend_handler)
        proxy_port = await self.start_proxy(backend_port)
        reader, writer = await self.connect(proxy_port)
        self.assertEqual(await authenticate(reader, writer), b'\x01\x00')
        writer.write(CONNECT_REQUEST + payload)
        await writer.drain()
        writer.write_eof()

        response = await reader.readexactly(len(CONNECT_REPLY))
        data = await read_to_eof(reader)
        writer.close()
        await writer.wait_closed()

        self.assertEqual(response, CONNECT_REPLY)
        self.assertEqual(data, b'backend:' + payload)
        self.assertEqual(received, {
            'greeting': b'\x05\x01\x00',
            'request': CONNECT_REQUEST,
            'payload': payload,
        })
        self.assertEqual(backend_errors, [])

    async def test_authentication_required_and_failures_are_generic(self):
        backend_connections = 0

        async def backend_handler(reader, writer):
            nonlocal backend_connections
            backend_connections += 1
            writer.close()
            await writer.wait_closed()

        self.backend, backend_port = await start_listener(backend_handler)
        proxy_port = await self.start_proxy(backend_port)
        stderr, stdout = io.StringIO(), io.StringIO()

        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            reader, writer = await self.connect(proxy_port)
            writer.write(b'\x05\x01\x00')
            await writer.drain()
            self.assertEqual(await reader.readexactly(2), b'\x05\xff')
            self.assertEqual(await reader.read(), b'')
            writer.close()
            await writer.wait_closed()

            reader, writer = await self.connect(proxy_port)
            writer.write(b'\x05\x02\x00\x02')
            await writer.drain()
            self.assertEqual(await reader.readexactly(2), b'\x05\x02')
            writer.close()
            await writer.wait_closed()

            reader, writer = await self.connect(proxy_port)
            self.assertEqual(
                await authenticate(reader, writer, password='wrong-secret'), b'\x01\x01')
            self.assertEqual(await reader.read(), b'')
            writer.close()
            await writer.wait_closed()

        self.assertEqual(backend_connections, 0)
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(stderr.getvalue(), '')

    async def test_malformed_and_eof_inputs_close_cleanly(self):
        async def unused_backend(reader, writer):
            writer.close()
            await writer.wait_closed()

        self.backend, backend_port = await start_listener(unused_backend)
        proxy_port = await self.start_proxy(backend_port)

        reader, writer = await self.connect(proxy_port)
        writer.write(b'\x05')
        await writer.drain()
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
        writer.close()
        await writer.wait_closed()

        reader, writer = await self.connect(proxy_port)
        writer.write(b'\x05\x00')
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 1), b'\x05\xff')
        self.assertEqual(await reader.read(), b'')
        writer.close()
        await writer.wait_closed()

        reader, writer = await self.connect(proxy_port)
        writer.write(b'\x05\x01\x02')
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b'\x05\x02')
        writer.write(b'\x02\x01')
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b'\x01\x01')
        self.assertEqual(await reader.read(), b'')
        writer.close()
        await writer.wait_closed()

    async def test_backend_unavailable_never_reports_auth_success(self):
        temporary = await asyncio.start_server(lambda r, w: None, '127.0.0.1', 0)
        backend_port = temporary.sockets[0].getsockname()[1]
        temporary.close()
        await temporary.wait_closed()
        proxy_port = await self.start_proxy(backend_port)
        reader, writer = await self.connect(proxy_port)

        result = await authenticate(reader, writer)
        remaining = await reader.read()
        writer.close()
        await writer.wait_closed()

        self.assertEqual(result, b'\x01\x01')
        self.assertEqual(remaining, b'')

    async def test_connection_limit_closes_new_clients_without_waiting(self):
        backend, backend_port = await start_listener(
            lambda reader, writer: _close_test_writer(writer))
        self.backend = backend
        proxy_port = await self.start_proxy(
            backend_port, max_connections=1, handshake_timeout=2)

        first_reader, first_writer = await self.connect(proxy_port)
        first_writer.write(b'\x05\x01\x02')
        await first_writer.drain()
        self.assertEqual(await first_reader.readexactly(2), b'\x05\x02')

        second_reader, second_writer = await self.connect(proxy_port)
        second_writer.write(b'\x05\x01\x02')
        await second_writer.drain()
        try:
            self.assertEqual(await asyncio.wait_for(second_reader.read(), 1), b'')
        except ConnectionResetError:
            pass
        second_writer.close()
        with contextlib.suppress(ConnectionResetError):
            await second_writer.wait_closed()

        first_writer.close()
        await first_writer.wait_closed()
        for _ in range(20):
            if self.proxy.active_connections == 0:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(self.proxy.active_connections, 0)

    async def test_handshake_timeout_is_injectable(self):
        async def unused_backend(reader, writer):
            writer.close()
            await writer.wait_closed()

        self.backend, backend_port = await start_listener(unused_backend)
        proxy_port = await self.start_proxy(backend_port, handshake_timeout=0.03)
        reader, writer = await self.connect(proxy_port)

        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
        writer.close()
        await writer.wait_closed()

    async def test_tls_auth_relay_and_backend_eof_close_tls_stream(self):
        payload = b'backend response\x00\xff'
        received = {}

        async def backend_handler(reader, writer):
            try:
                received['greeting'] = await reader.readexactly(3)
                writer.write(b'\x05\x00')
                await writer.drain()
                received['request'] = await reader.readexactly(len(CONNECT_REQUEST))
                writer.write(CONNECT_REPLY + payload)
                await writer.drain()
                writer.write_eof()
            finally:
                writer.close()
                await writer.wait_closed()

        self.backend, backend_port = await start_listener(backend_handler)
        with temporary_tls_certificates() as fixture:
            context = load_tls_context({'cert': fixture.cert_pem, 'key': fixture.key_pem})
            self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
            proxy_port = await self.start_proxy(backend_port, ssl_context=context)
            client_context = fixture.trusted_client_context()
            reader, writer = await asyncio.open_connection(
                '127.0.0.1', proxy_port, ssl=client_context, server_hostname='localhost')
            self.assertEqual(await authenticate(reader, writer), b'\x01\x00')
            writer.write(CONNECT_REQUEST)
            await writer.drain()
            self.assertEqual(await reader.readexactly(len(CONNECT_REPLY)), CONNECT_REPLY)
            self.assertEqual(await asyncio.wait_for(read_to_eof(reader), 2), payload)
            writer.close()
            await writer.wait_closed()

        self.assertEqual(received, {
            'greeting': b'\x05\x01\x00',
            'request': CONNECT_REQUEST,
        })

    async def test_tls_rejects_plain_untrusted_and_wrong_hostname_clients(self):
        backend_connections = 0

        async def backend_handler(reader, writer):
            nonlocal backend_connections
            backend_connections += 1
            writer.close()
            await writer.wait_closed()

        self.backend, backend_port = await start_listener(backend_handler)
        with temporary_tls_certificates() as fixture:
            context = load_tls_context({'cert': fixture.cert_pem, 'key': fixture.key_pem})
            proxy_port = await self.start_proxy(backend_port, ssl_context=context)

            reader, writer = await self.connect(proxy_port)
            writer.write(b'\x05\x01\x02')
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(1), 0.05)
            except (asyncio.TimeoutError, ConnectionResetError):
                data = b''
            self.assertEqual(data, b'')
            writer.close()
            with contextlib.suppress(ConnectionResetError, ssl.SSLError):
                await writer.wait_closed()

            for client_context, server_hostname in (
                    (ssl.create_default_context(), 'localhost'),
                    (fixture.trusted_client_context(), 'wrong.example')):
                with self.assertRaises((ssl.SSLError, OSError)):
                    await asyncio.wait_for(
                        asyncio.open_connection(
                            '127.0.0.1', proxy_port, ssl=client_context,
                            server_hostname=server_hostname),
                        2)

        self.assertEqual(backend_connections, 0)

    def test_credentials_are_bounded_json_and_never_logged(self):
        payload = json.dumps([USERNAME, PASSWORD], ensure_ascii=False).encode()
        self.assertEqual(read_credentials(io.BytesIO(payload)), (USERNAME, PASSWORD, None))
        with self.assertRaises(ValueError):
            read_credentials(io.BytesIO(b'[]'))
        with self.assertRaises(ValueError):
            read_credentials(io.BytesIO(json.dumps(['u\x00', 'p']).encode()))
        tls_payload = json.dumps([
            USERNAME, PASSWORD, {'cert': 'CERT', 'key': 'KEY'}]).encode()
        self.assertEqual(
            read_credentials(io.BytesIO(tls_payload)),
            (USERNAME, PASSWORD, {'cert': 'CERT', 'key': 'KEY'}))
        with self.assertRaises(ValueError):
            read_credentials(io.BytesIO(b' ' * (128 * 1024 + 1)))
        with self.assertRaises(ValueError):
            read_credentials(io.BytesIO(b' ' * 4097), max_bytes=4096)
        with self.assertRaises(ValueError):
            read_credentials(io.BytesIO(json.dumps([
                USERNAME, PASSWORD, {'cert': 'CERT'}]).encode()))
        with temporary_tls_certificates() as fixture:
            with tempfile.TemporaryDirectory() as temporary:
                with mock.patch('auth_proxy.tempfile.tempdir', temporary):
                    load_tls_context({'cert': fixture.cert_pem, 'key': fixture.key_pem})
                self.assertEqual(list(Path(temporary).iterdir()), [])

    async def test_close_writer_aborts_after_bounded_wait(self):
        class StuckWriter:
            def __init__(self):
                self.transport = self
                self.aborted = False

            def close(self):
                pass

            async def wait_closed(self):
                await asyncio.sleep(10)

            def abort(self):
                self.aborted = True

        writer = StuckWriter()
        with mock.patch('auth_proxy.CLOSE_TIMEOUT', 0.01):
            await _close_writer(writer)
        self.assertTrue(writer.aborted)


async def _close_test_writer(writer):
    writer.close()
    await writer.wait_closed()


if __name__ == '__main__':
    unittest.main()
