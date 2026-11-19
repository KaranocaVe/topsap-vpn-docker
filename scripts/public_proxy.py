#!/usr/bin/env python3
"""Find a public HTTP CONNECT proxy that reaches the official HTTPS catalog."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.client import HTTPException
import ipaddress
from itertools import islice, zip_longest
import json
import subprocess
from urllib.parse import urlsplit
from urllib.request import urlopen

GEONODE = 'https://proxylist.geonode.com/api/proxy-list?country=CN&protocols=http%2Chttps&limit=100&page=1&sort_by=lastChecked&sort_type=desc'
SOURCES = (
    GEONODE,
    'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/countries/CN/data.txt',
    'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=8000&country=cn&ssl=yes&anonymity=all',
    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
    'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt',
)
TARGET = 'https://app.topsec.com.cn/'
MAX_CANDIDATES = 300


def geonode_entries(data):
    rows = data.get('data', []) if isinstance(data, dict) else []
    if not isinstance(rows, list):
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        host, port = row.get('ip'), row.get('port')
        if not isinstance(host, str) or not isinstance(port, (str, int)):
            continue
        if ':' in host and not host.startswith('['):
            host = '[' + host + ']'
        yield f'http://{host}:{port}'


def source_candidates(source):
    try:
        with urlopen(source, timeout=10) as response:
            raw = response.read(1024 * 1024).decode()
        entries = geonode_entries(json.loads(raw)) if source == GEONODE else raw.splitlines()
    except (OSError, HTTPException, ValueError):
        return []
    result = {}
    for entry in entries:
        try:
            proxy = entry.strip()
            if '://' not in proxy:
                proxy = 'http://' + proxy
            parsed = urlsplit(proxy)
            if (parsed.scheme not in ('http', 'https') or parsed.username is not None
                    or not parsed.port or parsed.path not in ('', '/')
                    or parsed.query or parsed.fragment):
                continue
            address = ipaddress.ip_address(parsed.hostname)
            if not address.is_global or address.is_multicast or '%' in str(address):
                continue
            # Lists use 'https' to denote CONNECT support.
            host = f'[{address}]' if address.version == 6 else str(address)
            result[f'http://{host}:{parsed.port}'] = None
        except ValueError:
            continue
    return list(result)


def candidates():
    with ThreadPoolExecutor(max_workers=len(SOURCES)) as pool:
        lists = list(pool.map(source_candidates, SOURCES))
    # Give each source a share of the probe budget.
    ordered = dict.fromkeys(proxy for row in zip_longest(*lists) for proxy in row if proxy)
    return list(islice(ordered, MAX_CANDIDATES))


def probe(proxy):
    command = ['curl', '-q', '--silent', '--show-error', '--fail', '--noproxy', '',
               '--proto', '=https', '--connect-timeout', '4', '--max-time', '12',
               '--max-filesize', '1048576', '--proxy', proxy, TARGET]
    try:
        result = subprocess.run(command, capture_output=True, timeout=14)
        if result.returncode == 0 and b'TopSAP' in result.stdout:
            return proxy
    except subprocess.TimeoutExpired:
        pass
    return None


def find_proxies():
    available = candidates()
    print('Probing', len(available), 'public CONNECT endpoints', flush=True)
    good = []
    with ThreadPoolExecutor(max_workers=24) as pool:
        for future in as_completed([pool.submit(probe, proxy) for proxy in available]):
            proxy = future.result()
            if proxy:
                good.append(proxy)
    print(len(good), 'proxies reached the official HTTPS catalog', flush=True)
    if not good:
        raise OSError('No public proxy reached the official HTTPS catalog')
    return good


def main():
    print(json.dumps({'proxies': find_proxies()}))


if __name__ == '__main__':
    main()
