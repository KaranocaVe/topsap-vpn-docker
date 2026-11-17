import asyncio
import contextlib
import hmac
import json
import sys


DEFAULT_HANDSHAKE_TIMEOUT = 10.0
DEFAULT_MAX_CONNECTIONS = 64
STREAM_LIMIT = 64 * 1024
RELAY_CHUNK_SIZE = 64 * 1024
CLOSE_TIMEOUT = 1.0


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


def read_credentials(stream, *, max_bytes=4096):
    raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError('Invalid credential input')
    try:
        values = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError('Invalid credential input') from None
    if (not isinstance(values, list) or len(values) != 2
            or any(not isinstance(value, str) for value in values)):
        raise ValueError('Invalid credential input')
    try:
        _credential_bytes(values[0])
        _credential_bytes(values[1])
    except ValueError:
        raise ValueError('Invalid credential input') from None
    return values[0], values[1]


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


async def _relay(client_reader, client_writer, backend_reader, backend_writer):
    tasks = {
        asyncio.create_task(_pipe(client_reader, backend_writer)),
        asyncio.create_task(_pipe(backend_reader, client_writer)),
    }
    try:
        await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


class AuthProxy:
    def __init__(self, username, password, *, host='0.0.0.0', port=1080,
                 backend_host='127.0.0.1', backend_port=1081,
                 handshake_timeout=DEFAULT_HANDSHAKE_TIMEOUT,
                 max_connections=DEFAULT_MAX_CONNECTIONS):
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
        self._server = None
        self._connections = set()
        self._tasks = set()

    @property
    def active_connections(self):
        return len(self._connections)

    async def start(self):
        if self._server is not None:
            raise RuntimeError('Proxy is already started')
        self._server = await asyncio.start_server(
            self._accept, self.host, self.port, limit=STREAM_LIMIT)
        return self

    async def serve_forever(self):
        await self.start()
        try:
            async with self._server:
                await self._server.serve_forever()
        finally:
            await self.close()

    async def close(self):
        server, self._server = self._server, None
        if server is not None:
            server.close()
            await server.wait_closed()
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

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
        username, password = read_credentials(sys.stdin.buffer)
        asyncio.run(AuthProxy(username, password).serve_forever())
    except KeyboardInterrupt:
        return 0
    except Exception:
        print('auth-proxy: service failed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
