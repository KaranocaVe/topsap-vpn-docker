#!/usr/bin/env python3
"""Find a public HTTP CONNECT proxy that reaches the official HTTPS catalog."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import json
import subprocess
from urllib.parse import urlsplit
from urllib.request import urlopen

SOURCES = (
    'https://proxylist.geonode.com/api/proxy-list?country=CN&protocols=http%2Chttps&limit=100&page=1&sort_by=lastChecked&sort_type=desc',
    'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/countries/CN/data.txt',
)
TARGET = 'https://app.topsec.com.cn/'


def candidates():
    proxies = []
    for source in SOURCES:
        try:
            with urlopen(source, timeout=20) as response:
                raw = response.read(1024 * 1024).decode()
            if source == SOURCES[0]:
                rows = json.loads(raw)['data']
                proxies.extend('http://' + row['ip'] + ':' + row['port'] for row in rows)
            else:
                proxies.extend(raw.splitlines())
        except (OSError, ValueError, KeyError):
            continue
    result = []
    for proxy in proxies:
        try:
            parsed = urlsplit(proxy)
            if (parsed.scheme not in ('http', 'https') or parsed.username or parsed.password
                    or not ipaddress.ip_address(parsed.hostname).is_global
                    or not 0 < parsed.port < 65536):
                continue
            # Lists use 'https' to denote CONNECT support, not TLS to the proxy.
            value = 'http://' + parsed.hostname + ':' + str(parsed.port)
            if value not in result:
                result.append(value)
        except ValueError:
            continue
    return result[:120]


def probe(proxy):
    command = ['curl', '--silent', '--show-error', '--fail', '--noproxy', '',
               '--proto', '=https', '--connect-timeout', '4', '--max-time', '12',
               '--max-filesize', '1048576', '--proxy', proxy, TARGET]
    try:
        result = subprocess.run(command, capture_output=True, timeout=14)
        if result.returncode == 0 and b'TopSAP' in result.stdout:
            return proxy
    except subprocess.TimeoutExpired:
        pass
    return None


def main():
    available = candidates()
    print('Probing', len(available), 'public CONNECT endpoints', flush=True)
    good = []
    with ThreadPoolExecutor(max_workers=12) as pool:
        for future in as_completed([pool.submit(probe, proxy) for proxy in available]):
            proxy = future.result()
            if proxy:
                good.append(proxy)
                print('TLS-verified official catalog via', proxy, flush=True)
    if not good:
        raise SystemExit('No public proxy reached the official HTTPS catalog')
    print(json.dumps({'proxies': good}))


if __name__ == '__main__':
    main()
