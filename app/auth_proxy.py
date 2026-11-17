import asyncio
import contextlib
import hmac
import json
import os
import pathlib
import ssl
import sys
import tempfile


DEFAULT_HANDSHAKE_TIMEOUT = 10.0
DEFAULT_MAX_CONNECTIONS = 64
STREAM_LIMIT = 64 * 1024
RELAY_CHUNK_SIZE = 64 * 1024
CLOSE_TIMEOUT = 1.0
MAX_CREDENTIAL_INPUT = 128 * 1024


def _credential_bytes(value):
    if not isinstance(value, str):
        raise ValueError('Invalid SOCKS credentials')
    try:
        encoded = value.encode('utf-8')
    except UnicodeEncodeError:
        raise ValueError('Invalid SOCKS credentials') from None
    if not 1 <= len(encoded) <= 255 or b'\0' in encoded:
        raise ValueError('Invalid SOCKS credentials')
    return encoded


def read_credentials(stream, *, max_bytes=MAX_CREDENTIAL_INPUT):
    raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError('Invalid credential input')
    try:
        values = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError('Invalid credential input') from None
    if (not isinstance(values, list) or len(values) not in (2, 3)
            or not isinstance(values[0], str) or not isinstance(values[1], str)):
        raise ValueError('Invalid credential input')
    tls_material = None
    if len(values) == 3:
        tls_material = values[2]
        if (not isinstance(tls_material, dict)
                or set(tls_material) != {'cert', 'key'}
                or not isinstance(tls_material['cert'], str)
                or not isinstance(tls_material['key'], str)
                or not tls_material['cert'] or not tls_material['key']):
            raise ValueError('Invalid credential input')
    try:
        _credential_bytes(values[0])
        _credential_bytes(values[1])
    except ValueError:
        raise ValueError('Invalid credential input') from None
    return values[0], values[1], tls_material


def _write_private_file(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
        output.write(content)


def load_tls_context(tls_material):
    if tls_material is None:
        return None
    with tempfile.TemporaryDirectory(prefix='topsap-auth-tls-') as directory:
        os.chmod(directory, 0o700)
        cert_path = pathlib.Path(directory) / 'server-cert.pem'
        key_path = pathlib.Path(directory) / 'server-key.pem'
        _write_private_file(cert_path, tls_material['cert'])
        _write_private_file(key_path, tls_material['key'])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        cert_path.unlink()
        key_path.unlink()
        return context


async def _close_writer(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), CLOSE_TIMEOUT)
    except asyncio.TimeoutError:
        transport = getattr(writer, 'transport', None)
        if transport is not None:
            transport.abort()
    except Exception:
        pass


async def _pipe(reader, writer):
    while data := await reader.read(RELAY_CHUNK_SIZE):
        writer.write(data)
        await writer.drain()
    if writer.can_write_eof():
        writer.write_eof()
        await writer.drain()
        return True
    return False


async def _relay(client_reader, client_writer, backend_reader, backend_writer):
    tasks = {
        asyncio.create_task(_pipe(client_reader, backend_writer)),
        asyncio.create_task(_pipe(backend_reader, client_writer)),
    }
    try:
        while tasks:
            done, tasks = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED)
            if any(not task.result() for task in done):
                client_writer.close()
                backend_writer.close()
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                return
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


class AuthProxy:
    def __init__(self, username, password, *, host='0.0.0.0', port=1080,
                 backend_host='127.0.0.1', backend_port=1081,
                 handshake_timeout=DEFAULT_HANDSHAKE_TIMEOUT,
                 max_connections=DEFAULT_MAX_CONNECTIONS, ssl_context=None):
        if handshake_timeout <= 0 or max_connections < 1:
            raise ValueError('Invalid proxy limits')
        self.username = _credential_bytes(username)
        self.password = _credential_bytes(password)
        self.host = host
        self.port = port
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.handshake_timeout = handshake_timeout
        self.max_connections = max_connections
        self.ssl_context = ssl_context
        self._server = None
        self._connections = set()
        self._tasks = set()
        self._loop = None
        self._previous_exception_handler = None
        self._tls_exception_handler = None

    @property
    def active_connections(self):
        return len(self._connections)

    async def start(self):
        if self._server is not None:
            raise RuntimeError('Proxy is already started')
        server_options = {'limit': STREAM_LIMIT}
        if self.ssl_context is not None:
            self._loop = asyncio.get_running_loop()
            self._previous_exception_handler = self._loop.get_exception_handler()
            self._tls_exception_handler = self._handle_loop_exception
            self._loop.set_exception_handler(self._tls_exception_handler)
            server_options.update(
                ssl=self.ssl_context,
                ssl_handshake_timeout=self.handshake_timeout,
                ssl_shutdown_timeout=CLOSE_TIMEOUT)
        try:
            self._server = await asyncio.start_server(
                self._accept, self.host, self.port, **server_options)
        except BaseException:
            self._restore_loop_exception_handler()
            raise
        return self

    def _handle_loop_exception(self, loop, context):
        error = context.get('exception')
        if (context.get('message') == 'Error on transport creation for incoming connection'
                and isinstance(error, (ConnectionError, ssl.SSLError))):
            return
        if self._previous_exception_handler is not None:
            self._previous_exception_handler(loop, context)
        else:
            loop.default_exception_handler(context)

    def _restore_loop_exception_handler(self):
        if (self._loop is not None
                and self._loop.get_exception_handler() is self._tls_exception_handler):
            self._loop.set_exception_handler(self._previous_exception_handler)
        self._loop = None
        self._previous_exception_handler = None
        self._tls_exception_handler = None

    async def serve_forever(self):
        await self.start()
        try:
            async with self._server:
                await self._server.serve_forever()
        finally:
            await self.close()

    async def close(self):
        server, self._server = self._server, None
        try:
            if server is not None:
                server.close()
                await server.wait_closed()
            tasks = tuple(self._tasks)
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            self._restore_loop_exception_handler()

    def _track(self, task, *, connection=False):
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        if connection:
            self._connections.add(task)
            task.add_done_callback(self._connections.discard)

    def _accept(self, reader, writer):
        if len(self._connections) >= self.max_connections:
            task = asyncio.create_task(_close_writer(writer))
            self._track(task)
            return
        task = asyncio.create_task(self._handle(reader, writer))
        self._track(task, connection=True)

    async def _authenticate(self, reader, writer):
        version, method_count = await reader.readexactly(2)
        methods = await reader.readexactly(method_count)
        if version != 5 or 2 not in methods:
            writer.write(b'\x05\xff')
            await writer.drain()
            return False

        writer.write(b'\x05\x02')
        await writer.drain()
        auth_version, username_size = await reader.readexactly(2)
        if auth_version != 1 or username_size == 0:
            await self._send_auth_failure(writer)
            return False

        username = await reader.readexactly(username_size)
        password_size = (await reader.readexactly(1))[0]
        if password_size == 0:
            await self._send_auth_failure(writer)
            return False
        password = await reader.readexactly(password_size)
        username_ok = hmac.compare_digest(username, self.username)
        password_ok = hmac.compare_digest(password, self.password)
        if not (username_ok & password_ok):
            await self._send_auth_failure(writer)
            return False
        return True

    @staticmethod
    async def _send_auth_failure(writer):
        writer.write(b'\x01\x01')
        await writer.drain()

    async def _handle(self, client_reader, client_writer):
        backend_writer = None
        credentials_valid = False
        auth_succeeded = False
        try:
            async with asyncio.timeout(self.handshake_timeout):
                credentials_valid = await self._authenticate(client_reader, client_writer)
                if not credentials_valid:
                    return

                backend_reader, backend_writer = await asyncio.open_connection(
                    self.backend_host, self.backend_port, limit=STREAM_LIMIT)
                backend_writer.write(b'\x05\x01\x00')
                await backend_writer.drain()
                if await backend_reader.readexactly(2) != b'\x05\x00':
                    raise ConnectionError('Invalid backend method response')

                client_writer.write(b'\x01\x00')
                await client_writer.drain()
                auth_succeeded = True

            await _relay(client_reader, client_writer, backend_reader, backend_writer)
        except asyncio.CancelledError:
            raise
        except Exception:
            if credentials_valid and not auth_succeeded:
                with contextlib.suppress(Exception):
                    await self._send_auth_failure(client_writer)
        finally:
            await _close_writer(client_writer)
            if backend_writer is not None:
                await _close_writer(backend_writer)


def main():
    try:
        username, password, tls_material = read_credentials(sys.stdin.buffer)
        ssl_context = load_tls_context(tls_material)
        proxy = AuthProxy(username, password, ssl_context=ssl_context)
        del username, password, tls_material
        asyncio.run(proxy.serve_forever())
    except KeyboardInterrupt:
        return 0
    except Exception:
        print('auth-proxy: service failed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
