#!/usr/bin/env python3
"""Open an authenticated SOCKS5 stream, optionally over verified TLS."""
import argparse
import asyncio
import contextlib
import ipaddress
import os
from pathlib import Path
import select
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import config
import network

BUFFER_SIZE = 65536
IO_TIMEOUT = 20
TLS_EOF_DRAIN_TIMEOUT = 2


class QuietParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('invalid arguments')


def parser():
    result = QuietParser(description=__doc__)
    result.add_argument('--credentials', required=True, metavar='PATH')
    result.add_argument('--ssh', metavar='SSH_ALIAS')
    result.add_argument('--proxy-host', default='127.0.0.1')
    result.add_argument('--proxy-port', type=int, default=1080)
    result.add_argument('--tls', action='store_true')
    result.add_argument('--tls-ca', metavar='PATH')
    result.add_argument('--tls-server-name', metavar='NAME')
    result.add_argument('host')
    result.add_argument('port', type=int)
    return result


def read_credentials(path):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK
                         | getattr(os, 'O_NOFOLLOW', 0))
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError('invalid credentials file')

        # Parse through the already-open descriptor so a path swap cannot
        # redirect the parser to another file after the ownership check.
        descriptor_path = f'/proc/self/fd/{descriptor}'
        if not os.path.exists(descriptor_path):
            descriptor_path = f'/dev/fd/{descriptor}'
        values = config.read_env(descriptor_path)
        if set(values) != {'SOCKS_USERNAME', 'SOCKS_PASSWORD'}:
            raise ValueError('invalid credentials file')
        username = values['SOCKS_USERNAME']
        password = values['SOCKS_PASSWORD']
        if not username or not password:
            raise ValueError('invalid credentials file')
        return username, password
    finally:
        os.close(descriptor)


def ssh_command(alias, proxy_host, proxy_port):
    destination = f'[{proxy_host}]' if ':' in proxy_host else proxy_host
    return [
        'ssh', '-T',
        '-o', 'BatchMode=yes',
        '-o', 'ClearAllForwardings=yes',
        '-o', 'ConnectTimeout=20',
        '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3',
        '-o', 'ControlMaster=no',
        '-o', 'ControlPath=none',
        '-o', 'ControlPersist=no',
        '-W', f'{destination}:{proxy_port}', alias,
    ]


class PipeSocket:
    """Socket-like access to an OpenSSH process's binary stdio pipes."""

    def __init__(self, writer, reader, timeout=IO_TIMEOUT):
        self.writer = writer
        self.reader = reader
        self.timeout = timeout

    def _wait(self, fd, writable=False, deadline=None):
        remaining = self.timeout if deadline is None else deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('SSH tunnel I/O timed out')
        readable, writable_fds, _ = select.select(
            [] if writable else [fd], [fd] if writable else [], [], remaining)
        if not (writable_fds if writable else readable):
            raise TimeoutError('SSH tunnel I/O timed out')

    def recv(self, size):
        self._wait(self.reader.fileno())
        return os.read(self.reader.fileno(), size)

    def sendall(self, data):
        view = memoryview(data)
        deadline = time.monotonic() + self.timeout
        fd = self.writer.fileno()
        while view:
            self._wait(fd, writable=True, deadline=deadline)
            written = os.write(fd, view)
            if not written:
                raise BrokenPipeError('SSH tunnel closed')
            view = view[written:]

    def fileno(self):
        return self.reader.fileno()

    def close_write(self):
        if not self.writer.closed:
            self.writer.close()

    def close(self):
        self.close_write()
        if not self.reader.closed:
            self.reader.close()


def _read(endpoint, size):
    if isinstance(endpoint, PipeSocket):
        return os.read(endpoint.reader.fileno(), size)
    return endpoint.recv(size)


def _write(endpoint, data):
    if isinstance(endpoint, PipeSocket):
        return os.write(endpoint.writer.fileno(), data)
    return endpoint.send(data)


def _close_write(endpoint):
    if isinstance(endpoint, PipeSocket):
        endpoint.close_write()
    else:
        try:
            endpoint.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def relay(endpoint, stdin_fd=None, stdout_fd=None):
    """Relay stdin/stdout with bounded buffers and TCP-style half-close."""
    stdin_fd = sys.stdin.fileno() if stdin_fd is None else stdin_fd
    stdout_fd = sys.stdout.fileno() if stdout_fd is None else stdout_fd
    read_fd = endpoint.reader.fileno() if isinstance(endpoint, PipeSocket) else endpoint.fileno()
    write_fd = endpoint.writer.fileno() if isinstance(endpoint, PipeSocket) else endpoint.fileno()
    endpoint_flags = [(read_fd, os.get_blocking(read_fd))]
    if write_fd != read_fd:
        endpoint_flags.append((write_fd, os.get_blocking(write_fd)))
    for fd, _ in endpoint_flags:
        os.set_blocking(fd, False)
    stdout_blocking = os.get_blocking(stdout_fd)
    os.set_blocking(stdout_fd, False)

    to_endpoint = bytearray()
    to_stdout = bytearray()
    stdin_open = True
    endpoint_read_open = True
    write_open = True

    try:
        while stdin_open or to_endpoint or endpoint_read_open or to_stdout:
            readable = []
            writable = []
            if stdin_open and write_open and len(to_endpoint) < BUFFER_SIZE:
                readable.append(stdin_fd)
            if endpoint_read_open and len(to_stdout) < BUFFER_SIZE:
                readable.append(read_fd)
            if write_open and to_endpoint:
                writable.append(write_fd)
            if to_stdout:
                writable.append(stdout_fd)
            if not readable and not writable:
                break

            ready_read, ready_write, _ = select.select(readable, writable, [])

            if stdin_fd in ready_read:
                data = os.read(stdin_fd, min(BUFFER_SIZE - len(to_endpoint), BUFFER_SIZE))
                if data:
                    to_endpoint.extend(data)
                else:
                    stdin_open = False

            if endpoint_read_open and read_fd in ready_read:
                try:
                    data = _read(endpoint, min(BUFFER_SIZE - len(to_stdout), BUFFER_SIZE))
                except BlockingIOError:
                    data = None
                if data == b'':
                    endpoint_read_open = False
                elif data:
                    to_stdout.extend(data)

            if write_open and write_fd in ready_write and to_endpoint:
                try:
                    written = _write(endpoint, to_endpoint)
                except BlockingIOError:
                    written = 0
                except OSError:
                    write_open = False
                    to_endpoint.clear()
                    written = 0
                if written:
                    del to_endpoint[:written]

            if not stdin_open and write_open and not to_endpoint:
                _close_write(endpoint)
                write_open = False

            if stdout_fd in ready_write and to_stdout:
                try:
                    written = os.write(stdout_fd, to_stdout)
                except BlockingIOError:
                    written = 0
                if written:
                    del to_stdout[:written]

    finally:
        os.set_blocking(stdout_fd, stdout_blocking)
        for fd, blocking in endpoint_flags:
            try:
                os.set_blocking(fd, blocking)
            except OSError:
                pass


async def _read_fd(reader, source_file):
    loop = asyncio.get_running_loop()
    transport, _ = await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), source_file)
    return transport


class _WritePipeProtocol(asyncio.streams.FlowControlMixin):
    def __init__(self, loop):
        super().__init__(loop)
        self.closed = loop.create_future()

    def connection_lost(self, error):
        super().connection_lost(error)
        if not self.closed.done():
            self.closed.set_result(None)

    def _get_close_waiter(self, stream):
        return self.closed


async def _write_fd(destination_file):
    loop = asyncio.get_running_loop()
    protocol = _WritePipeProtocol(loop)
    transport, _ = await loop.connect_write_pipe(lambda: protocol, destination_file)
    return asyncio.StreamWriter(transport, protocol, None, loop)


async def _pipe_stream(reader, writer, idle_timeout=None):
    while True:
        if idle_timeout is None:
            data = await reader.read(BUFFER_SIZE)
        else:
            try:
                data = await asyncio.wait_for(reader.read(BUFFER_SIZE), idle_timeout)
            except asyncio.TimeoutError:
                return
        if not data:
            return
        writer.write(data)
        await writer.drain()


async def relay_tls(reader, writer, stdin_fd=None, stdout_fd=None):
    """Relay a TLS stream through bounded asyncio pipe transports."""
    stdin_fd = sys.stdin.fileno() if stdin_fd is None else stdin_fd
    stdout_fd = sys.stdout.fileno() if stdout_fd is None else stdout_fd
    stdin_file = os.fdopen(os.dup(stdin_fd), 'rb', buffering=0)
    stdout_file = os.fdopen(os.dup(stdout_fd), 'wb', buffering=0)
    stdin_transport = None
    stdout_writer = None
    tasks = set()
    try:
        stdin_reader = asyncio.StreamReader(limit=BUFFER_SIZE)
        stdin_transport = await _read_fd(stdin_reader, stdin_file)
        stdout_writer = await _write_fd(stdout_file)
        upload_task = asyncio.create_task(_pipe_stream(stdin_reader, writer))
        download_task = asyncio.create_task(_pipe_stream(reader, stdout_writer))
        tasks = {upload_task, download_task}
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        if upload_task in done and download_task not in done:
            # Cancel any unbounded read and restart with an idle deadline.
            # StreamReader keeps unread TLS plaintext buffered across cancellation.
            download_task.cancel()
            await asyncio.gather(download_task, return_exceptions=True)
            tasks.remove(download_task)
            await asyncio.wait_for(stdout_writer.drain(), timeout=IO_TIMEOUT)
            download_task = asyncio.create_task(
                _pipe_stream(reader, stdout_writer, TLS_EOF_DRAIN_TIMEOUT))
            tasks.add(download_task)
            await download_task
        else:
            for task in pending:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if stdin_transport is not None:
            stdin_transport.close()
        with contextlib.suppress(Exception):
            stdin_file.close()
        if stdout_writer is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(stdout_writer.drain(), timeout=1)
            stdout_writer.close()
            try:
                await asyncio.wait_for(stdout_writer.wait_closed(), timeout=1)
            except Exception:
                stdout_writer.transport.abort()
        else:
            with contextlib.suppress(Exception):
                stdout_file.close()


def _stop_child(process):
    if process is None:
        return
    if process.stdin:
        try:
            process.stdin.close()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    finally:
        if process.stdout:
            try:
                process.stdout.close()
            except OSError:
                pass


def _install_cleanup_signals():
    previous = {}

    def interrupt(signum, frame):
        # OpenSSH terminates ProxyCommand after a normal session exit too.
        # Unwind through run()'s cleanup without reporting a connection failure.
        raise SystemExit(128 + signum)

    for name in ('SIGTERM', 'SIGHUP'):
        value = getattr(signal, name, None)
        if value is not None:
            previous[value] = signal.getsignal(value)
            signal.signal(value, interrupt)
    return previous


def _restore_signals(previous):
    for sig, handler in previous.items():
        signal.signal(sig, handler)


async def socks_connect_tls(reader, writer, host, port, username, password):
    try:
        user = username.encode('utf-8')
        secret = password.encode('utf-8')
    except UnicodeEncodeError:
        raise ValueError('Invalid SOCKS credential') from None
    if (not 1 <= len(user) <= 255 or not 1 <= len(secret) <= 255
            or b'\0' in user or b'\0' in secret):
        raise ValueError('Invalid SOCKS credential')

    writer.write(b'\x05\x01\x02')
    await writer.drain()
    if await reader.readexactly(2) != b'\x05\x02':
        raise ConnectionError('SOCKS authentication negotiation failed')
    writer.write(b'\x01' + bytes([len(user)]) + user + bytes([len(secret)]) + secret)
    await writer.drain()
    if await reader.readexactly(2) != b'\x01\x00':
        raise ConnectionError('SOCKS username/password authentication failed')

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            encoded = host.encode('idna')
        except (AttributeError, UnicodeError):
            raise ValueError('Invalid SOCKS destination host') from None
        if not encoded or len(encoded) > 255 or b'\0' in encoded:
            raise ValueError('Invalid SOCKS destination host')
        address_type = b'\x03'
        address_bytes = bytes([len(encoded)]) + encoded
    else:
        address_type = b'\x01' if address.version == 4 else b'\x04'
        address_bytes = address.packed
    if not 1 <= port <= 65535:
        raise ValueError('Invalid SOCKS destination port')
    writer.write(b'\x05\x01\x00' + address_type + address_bytes + struct.pack('>H', port))
    await writer.drain()

    reply = await reader.readexactly(4)
    if reply[0] != 5:
        raise ConnectionError('Invalid SOCKS connect reply version')
    if reply[2] != 0:
        raise ConnectionError('Invalid SOCKS connect reply reserved field')
    if reply[3] == 1:
        address_size = 4
    elif reply[3] == 4:
        address_size = 16
    elif reply[3] == 3:
        address_size = (await reader.readexactly(1))[0]
        if not address_size:
            raise ConnectionError('Invalid SOCKS connect reply address')
    else:
        raise ConnectionError('Invalid SOCKS connect reply address type')
    await reader.readexactly(address_size + 2)
    if reply[1] != 0:
        raise ConnectionError('SOCKS destination connection failed')


def tls_context(ca_file=None):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


async def _run_tls(args, username, password, server_name, stdin_fd, stdout_fd):
    context = tls_context(args.tls_ca)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            args.proxy_host, args.proxy_port, ssl=context,
            server_hostname=server_name, limit=BUFFER_SIZE),
        timeout=IO_TIMEOUT,
    )
    try:
        # asyncio completes certificate and hostname verification before SOCKS
        # credentials can enter the TLS application stream.
        await asyncio.wait_for(
            socks_connect_tls(reader, writer, args.host, args.port, username, password),
            timeout=IO_TIMEOUT,
        )
        await relay_tls(reader, writer, stdin_fd, stdout_fd)
        return 0
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1)
        except Exception:
            writer.transport.abort()


def run(args, stdin_fd=None, stdout_fd=None):
    if args.tls and args.ssh:
        raise ValueError('--tls cannot be combined with --ssh')
    if not args.tls and (args.tls_ca is not None or args.tls_server_name is not None):
        raise ValueError('--tls-ca and --tls-server-name require --tls')
    server_name = args.tls_server_name if args.tls_server_name is not None else args.proxy_host
    if args.tls and not server_name:
        raise ValueError('invalid TLS server name')

    username, password = read_credentials(args.credentials)
    if not 1 <= args.proxy_port <= 65535 or not 1 <= args.port <= 65535:
        raise ValueError('invalid port')

    if args.tls:
        return asyncio.run(_run_tls(
            args, username, password, server_name,
            sys.stdin.fileno() if stdin_fd is None else stdin_fd,
            sys.stdout.fileno() if stdout_fd is None else stdout_fd,
        ))

    endpoint = None
    process = None
    previous_signals = {}
    try:
        if args.ssh:
            previous_signals = _install_cleanup_signals()
            process = subprocess.Popen(
                ssh_command(args.ssh, args.proxy_host, args.proxy_port),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, bufsize=0,
            )
            endpoint = PipeSocket(process.stdin, process.stdout)
        else:
            raw_socket = socket.create_connection(
                (args.proxy_host, args.proxy_port), timeout=IO_TIMEOUT)
            endpoint = raw_socket
            endpoint.settimeout(IO_TIMEOUT)

        network.socks_connect(endpoint, args.host, args.port,
                              username=username, password=password)
        relay(endpoint, stdin_fd, stdout_fd)
        if process is not None:
            process.wait(timeout=1)
            if process.returncode:
                raise ConnectionError('SSH tunnel exited unsuccessfully')
        return 0
    finally:
        try:
            if process is not None:
                _stop_child(process)
            elif endpoint is not None:
                endpoint.close()
        finally:
            _restore_signals(previous_signals)


def main(argv=None, stdin_fd=None, stdout_fd=None):
    try:
        args = parser().parse_args(argv)
        return run(args, stdin_fd, stdout_fd)
    except KeyboardInterrupt:
        print('socks-connect: interrupted', file=sys.stderr)
        return 130
    except Exception:
        print('socks-connect: connection failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
