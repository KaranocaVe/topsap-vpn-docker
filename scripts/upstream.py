#!/usr/bin/env python3
"""Discover official TopSAP DEBs and fetch SHA256-locked build inputs."""
import argparse
import hashlib
from http.client import HTTPException
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

SOURCE = 'https://app.topsec.com.cn/'
ARCHES = ('amd64', 'arm64')
PACKAGE = re.compile(r'TopSAP-(?P<version>[0-9]+(?:\.[0-9]+)+)[_-](?P<arch>amd64|arm64)\.deb$')
MAX_PACKAGE_BYTES = 512 * 1024 * 1024


def official_url(url):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname != 'app.topsec.com.cn'
            or parsed.port not in (None, 443) or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise ValueError('Only HTTPS downloads from app.topsec.com.cn are allowed')
    return url


class OfficialRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, code, msg, headers,
                                        official_url(urljoin(req.full_url, newurl)))


OPENER = build_opener(OfficialRedirects())
PUBLIC_PROXY = False
PROXY_OPENERS = None
PROXY_INDEX = 0


class PackageMismatch(ValueError):
    pass


def network_openers():
    global PROXY_OPENERS
    if not PUBLIC_PROXY:
        return [OPENER]
    if PROXY_OPENERS is None:
        try:
            with OPENER.open(Request(SOURCE, method='HEAD'), timeout=8):
                pass
            PROXY_OPENERS = [OPENER]
        except (OSError, HTTPException):
            # Only official public downloads use these untrusted transports.
            # TLS validation and OfficialRedirects remain enabled end to end.
            from public_proxy import find_proxies
            PROXY_OPENERS = [build_opener(ProxyHandler({'https': proxy}), OfficialRedirects())
                             for proxy in find_proxies()]
    return PROXY_OPENERS


def rotate_proxy():
    global PROXY_INDEX
    PROXY_INDEX += 1


def open_url(url):
    request = Request(official_url(url), headers={'User-Agent': 'topsap-vpn-docker/1.0'})
    openers = network_openers()
    for attempt in range(3):
        try:
            return openers[PROXY_INDEX % len(openers)].open(request, timeout=30)
        except HTTPError as error:
            if error.code < 500 or attempt == 2:
                raise
        except (OSError, HTTPException):
            if attempt == 2:
                raise
        rotate_proxy()
        time.sleep(2 ** attempt)


class Links(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links = set()

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            href = dict(attrs).get('href', '')
            if href:
                self.links.add(urljoin(self.base, href))


def links_in(html, base):
    parser = Links(base)
    parser.feed(html)
    return parser.links


def fetch_links(url):
    with open_url(url) as response:
        content = response.read(2 * 1024 * 1024 + 1)
        if len(content) > 2 * 1024 * 1024:
            raise ValueError('Download catalog is unexpectedly large')
        return links_in(content.decode('utf-8-sig'), url)


def package_identity(url):
    official_url(url)
    match = PACKAGE.fullmatch(unquote(urlsplit(url).path.rsplit('/', 1)[-1]))
    if not match:
        raise ValueError('Unsupported TopSAP DEB filename')
    return match['arch'], match['version']


def choose_packages(urls):
    selected = {}
    for url in sorted(urls):
        try:
            arch, version = package_identity(url)
        except ValueError:
            continue
        key = tuple(int(part) for part in version.split('.'))
        if arch not in selected or key > selected[arch][0]:
            selected[arch] = (key, {'url': url, 'version': version, 'architecture': arch})
    if set(selected) != set(ARCHES):
        raise ValueError('Official catalog is missing a supported DEB architecture')
    return {arch: selected[arch][1] for arch in ARCHES}


def discover():
    urls = fetch_links(SOURCE) | fetch_links(urljoin(SOURCE, 'linux-more.html'))
    pages = sorted(url for url in urls if urlsplit(url).hostname == 'app.topsec.com.cn'
                   and re.fullmatch(r'/linux_client_[0-9]+\.html', urlsplit(url).path))
    for page in pages:
        urls |= fetch_links(page)
    return choose_packages(urls)


def read_lock(path):
    lock = json.loads(Path(path).read_text())
    if lock.get('schema') != 1 or lock.get('source') != SOURCE or set(lock.get('packages', {})) != set(ARCHES):
        raise ValueError('Unsupported or incomplete packages lock')
    for arch, record in lock['packages'].items():
        actual_arch, version = package_identity(record['url'])
        if (actual_arch != arch or record.get('architecture') != arch
                or record.get('version') != version
                or not re.fullmatch('[0-9a-f]{64}', record.get('sha256', ''))
                or not isinstance(record.get('size'), int)
                or not 0 < record['size'] <= MAX_PACKAGE_BYTES):
            raise ValueError('Invalid package lock entry: ' + arch)
    return lock


def fetch_package_once(url, output, expected=None):
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        digest, size = hashlib.sha256(), 0
        deadline = time.monotonic() + 15 * 60
        with open_url(url) as response, tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as stream:
            temporary = Path(stream.name)
            if (getattr(response, 'status', 200) != 200
                    or (hasattr(response, 'headers') and response.headers.get('Content-Range'))):
                raise HTTPException('Expected a complete HTTP 200 package response')
            length = response.headers.get('Content-Length') if hasattr(response, 'headers') else None
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > MAX_PACKAGE_BYTES:
                    raise ValueError('Package exceeds download size limit')
                if time.monotonic() > deadline:
                    raise TimeoutError('Package download exceeded 15 minutes')
                digest.update(block)
                stream.write(block)
        if length is not None and size != int(length):
            raise OSError('Truncated HTTP package response')
        result = {'sha256': digest.hexdigest(), 'size': size}
        if not size:
            raise ValueError('Empty package download')
        if expected and any(result[key] != expected[key] for key in result):
            raise PackageMismatch('Downloaded package does not match the committed lock: '
                                  + json.dumps(result, sort_keys=True))
        os.replace(temporary, target)
        temporary = None
        return result
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def fetch_package(url, output, expected=None):
    for attempt in range(3):
        try:
            return fetch_package_once(url, output, expected)
        except (OSError, HTTPException):
            if attempt == 2:
                raise
            rotate_proxy()
            print('Download transport failed; retrying with another available route', flush=True)
        except PackageMismatch:
            if not PUBLIC_PROXY or attempt == 2:
                raise
            rotate_proxy()
            print('Incomplete or mismatched package; rejecting it and trying another route', flush=True)


def update(path):
    packages = discover()
    output = Path(path)
    if output.exists():
        previous = read_lock(output)['packages']
        for arch in ARCHES:
            version = lambda record: tuple(map(int, record['version'].split('.')))
            if version(packages[arch]) < version(previous[arch]):
                raise ValueError('Refusing upstream version rollback for ' + arch)
    with tempfile.TemporaryDirectory(prefix='topsap-packages-') as directory:
        for arch, record in packages.items():
            print('Checking official ' + arch + ' package ' + record['version'], flush=True)
            record.update(fetch_package(record['url'], Path(directory) / (arch + '.deb')))
    lock = {'schema': 1, 'source': SOURCE, 'packages': packages}
    # Omit timestamps so unchanged upstream content produces no daily commit.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=output.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(lock, indent=2) + '\n')
        read_lock(temporary)
        os.replace(temporary, output)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    global PUBLIC_PROXY
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    refresh = commands.add_parser('update')
    refresh.add_argument('--output', default='packages.lock.json')
    download = commands.add_parser('download')
    download.add_argument('--arch', choices=ARCHES, required=True)
    download.add_argument('--output', required=True)
    download.add_argument('--lock', default='packages.lock.json')
    for command in (refresh, download):
        command.add_argument('--public-proxy', action='store_true',
                             help='If direct HTTPS fails, discover public CONNECT proxies for official files only')
    args = parser.parse_args()
    PUBLIC_PROXY = args.public_proxy
    if args.command == 'update':
        update(args.output)
    else:
        record = read_lock(args.lock)['packages'][args.arch]
        fetch_package(record['url'], args.output, record)
        print('Verified ' + args.arch + ' TopSAP ' + record['version'])


if __name__ == '__main__':
    main()
