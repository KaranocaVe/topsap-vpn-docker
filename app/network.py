import ipaddress
import json
import socket
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


def probe(host, port, proxy_host='127.0.0.1', proxy_port=1080):
    address = ipaddress.ip_address(host)
    with socket.create_connection((proxy_host, proxy_port), timeout=5) as sock:
        sock.sendall(b'\x05\x01\x00')
        if exact(sock, 2) != b'\x05\x00':
            raise ConnectionError('SOCKS authentication negotiation failed')
        sock.sendall(b'\x05\x01\x00' + bytes([1 if address.version == 4 else 4])
                     + address.packed + struct.pack('>H', port))
        reply = exact(sock, 4)
        if reply[:2] != b'\x05\x00':
            raise ConnectionError('SOCKS destination connection failed')
        size = {1: 4, 4: 16}.get(reply[3])
        if size is None:
            size = exact(sock, 1)[0]
        exact(sock, size + 2)


def install_firewall():
    # Proxy replies to accepted clients may use eth0. New outbound proxy
    # connections, including DNS, must use TUN, even after routes change.
    for tool in ('iptables', 'ip6tables'):
        subprocess.run([tool, '-w', '-N', 'TOPSAP_PROXY'], capture_output=True)
        command(tool, '-w', '-F', 'TOPSAP_PROXY')
        command(tool, '-w', '-A', 'TOPSAP_PROXY', '-m', 'conntrack',
                '--ctstate', 'ESTABLISHED', '--ctdir', 'REPLY', '-j', 'ACCEPT')
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
        command(tool, '-w', '-A', 'TOPSAP_INPUT', '-j', 'REJECT')
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
