import ipaddress
import json
import socket
import ssl
import struct
import subprocess
from urllib.parse import urlsplit


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10).stdout


def tunnel_for(address):
    routes = json.loads(command('ip', '-j', 'route', 'get', address))
    if not routes or not routes[0].get('dev'):
        return None
    device = routes[0]['dev']
    links = json.loads(command('ip', '-d', '-j', 'link', 'show', 'dev', device))
    if links and links[0].get('linkinfo', {}).get('info_kind') == 'tun' and 'UP' in links[0].get('flags', []):
        return device
    return None


def exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError('SOCKS stream closed')
        data += part
    return data


def _credential_bytes(value):
    if not isinstance(value, str):
        raise ValueError('Invalid SOCKS credential')
    try:
        encoded = value.encode('utf-8')
    except UnicodeEncodeError:
        raise ValueError('Invalid SOCKS credential') from None
    if b'\0' in encoded or not 1 <= len(encoded) <= 255:
        raise ValueError('Invalid SOCKS credential')
    return encoded


def socks_connect(sock, host, port, *, username=None, password=None):
    if (username is None) != (password is None):
        raise ValueError('SOCKS username and password must be provided together')
    if username is None:
        methods = b'\x00'
        credentials = None
    else:
        credentials = (_credential_bytes(username), _credential_bytes(password))
        methods = b'\x02'

    sock.sendall(b'\x05' + bytes([len(methods)]) + methods)
    negotiation = exact(sock, 2)
    expected_method = methods[0]
    if negotiation[0] != 5 or negotiation[1] != expected_method:
        raise ConnectionError('SOCKS authentication negotiation failed')

    if credentials is not None:
        user, secret = credentials
        sock.sendall(b'\x01' + bytes([len(user)]) + user
                     + bytes([len(secret)]) + secret)
        auth_reply = exact(sock, 2)
        if auth_reply[0] != 1 or auth_reply[1] != 0:
            raise ConnectionError('SOCKS username/password authentication failed')

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            address = host.encode('idna')
        except (AttributeError, UnicodeError):
            raise ValueError('Invalid SOCKS destination host') from None
        if not address or len(address) > 255 or b'\0' in address:
            raise ValueError('Invalid SOCKS destination host')
        atyp = b'\x03'
        encoded_address = bytes([len(address)]) + address
    else:
        atyp = b'\x01' if address.version == 4 else b'\x04'
        encoded_address = address.packed

    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('Invalid SOCKS destination port')
    sock.sendall(b'\x05\x01\x00' + atyp + encoded_address + struct.pack('>H', port))

    reply = exact(sock, 4)
    if reply[0] != 5:
        raise ConnectionError('Invalid SOCKS connect reply version')
    if reply[2] != 0:
        raise ConnectionError('Invalid SOCKS connect reply reserved field')
    if reply[3] == 1:
        size = 4
    elif reply[3] == 4:
        size = 16
    elif reply[3] == 3:
        size = exact(sock, 1)[0]
        if not size:
            raise ConnectionError('Invalid SOCKS connect reply address')
    else:
        raise ConnectionError('Invalid SOCKS connect reply address type')
    exact(sock, size + 2)
    if reply[1] != 0:
        raise ConnectionError('SOCKS destination connection failed')


def tls_probe_options(config):
    if config.get('SOCKS_TLS', '0') == '1':
        return {'tls_ca': '/run/secrets/socks-tls.crt',
                'tls_server_name': config['SOCKS_TLS_SERVER_NAME']}
    return {}


def probe(host, port, proxy_host='127.0.0.1', proxy_port=1080, *, username=None, password=None,
          tls_ca=None, tls_server_name=None):
    if tls_server_name is not None and tls_ca is None:
        raise ValueError('TLS server name requires a trusted certificate')
    with socket.create_connection((proxy_host, proxy_port), timeout=5) as sock:
        if tls_ca is None:
            socks_connect(sock, host, port, username=username, password=password)
        else:
            context = ssl.create_default_context(cafile=tls_ca)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            with context.wrap_socket(sock, server_hostname=tls_server_name or proxy_host) as secure:
                socks_connect(secure, host, port, username=username, password=password)


def install_firewall(*, tls=False):
    # Proxy replies to accepted clients may use eth0. New outbound proxy
    # connections, including DNS, must use TUN, even after routes change.
    for tool in ('iptables', 'ip6tables'):
        subprocess.run([tool, '-w', '-N', 'TOPSAP_PROXY'], capture_output=True)
        command(tool, '-w', '-F', 'TOPSAP_PROXY')
        command(tool, '-w', '-A', 'TOPSAP_PROXY', '-m', 'conntrack',
                '--ctstate', 'ESTABLISHED', '--ctdir', 'REPLY', '-j', 'ACCEPT')
        if tool == 'iptables':
            command(tool, '-w', '-A', 'TOPSAP_PROXY', '-o', 'lo', '-d', '127.0.0.1',
                    '-p', 'tcp', '--dport', '1081', '-j', 'ACCEPT')
        command(tool, '-w', '-A', 'TOPSAP_PROXY', '-o', 'tun+', '-j', 'ACCEPT')
        command(tool, '-w', '-A', 'TOPSAP_PROXY', '-j', 'REJECT')
        rule = ['OUTPUT', '-m', 'owner', '--uid-owner', '65534', '-j', 'TOPSAP_PROXY']
        if subprocess.run([tool, '-w', '-C', *rule], capture_output=True).returncode:
            command(tool, '-w', '-I', *rule)
    gateway = json.loads(command('ip', '-j', 'route', 'show', 'default'))[0]['gateway']
    for tool in ('iptables', 'ip6tables'):
        subprocess.run([tool, '-w', '-N', 'TOPSAP_INPUT'], capture_output=True)
        command(tool, '-w', '-F', 'TOPSAP_INPUT')
        command(tool, '-w', '-A', 'TOPSAP_INPUT', '-i', 'lo', '-j', 'ACCEPT')
        if tool == 'iptables':
            command(tool, '-w', '-A', 'TOPSAP_INPUT', '-s', gateway, '-j', 'ACCEPT')
        command(tool, '-w', '-A', 'TOPSAP_INPUT', '-j', 'ACCEPT' if tls else 'REJECT')
        rule = ['INPUT', '-p', 'tcp', '--dport', '1080', '-j', 'TOPSAP_INPUT']
        if subprocess.run([tool, '-w', '-C', *rule], capture_output=True).returncode:
            command(tool, '-w', '-I', *rule)


def gateway_firewall(address):
    parsed = urlsplit(address if '://' in address else '//' + address)
    if not parsed.hostname:
        raise ValueError('Invalid VPN_HOST')
    addresses = {item[4][0] for item in socket.getaddrinfo(
        parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)}
    for tool, version in (('iptables', 4), ('ip6tables', 6)):
        subprocess.run([tool, '-w', '-N', 'TOPSAP_CLIENT'], capture_output=True)
        command(tool, '-w', '-F', 'TOPSAP_CLIENT')
        command(tool, '-w', '-A', 'TOPSAP_CLIENT', '-m', 'conntrack',
                '--ctstate', 'ESTABLISHED', '--ctdir', 'REPLY', '-j', 'ACCEPT')
        for device in ('lo', 'tun+'):
            command(tool, '-w', '-A', 'TOPSAP_CLIENT', '-o', device, '-j', 'ACCEPT')
        for host in sorted(addresses):
            if ipaddress.ip_address(host).version == version:
                command(tool, '-w', '-A', 'TOPSAP_CLIENT', '-d', host, '-j', 'ACCEPT')
        command(tool, '-w', '-A', 'TOPSAP_CLIENT', '-j', 'REJECT')
        rule = ['OUTPUT', '-m', 'owner', '--uid-owner', '0', '-j', 'TOPSAP_CLIENT']
        if subprocess.run([tool, '-w', '-C', *rule], capture_output=True).returncode:
            command(tool, '-w', '-I', *rule)
