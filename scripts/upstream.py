#!/usr/bin/env python3
"""Discover official TopSAP DEBs and fetch SHA256-locked build inputs."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
import hashlib
from http.client import HTTPException
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import tempfile
from threading import Event, Lock
import time
from urllib.error import HTTPError
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
PROXY_WORKERS = 16


class PackageMismatch(ValueError):
    pass


def open_url(url, proxy):
    request = Request(official_url(url), headers={'User-Agent': 'topsap-vpn-docker/1.0'})
    if proxy is None:
        return OPENER.open(request, timeout=8 if PUBLIC_PROXY else 30)
    opener = build_opener(ProxyHandler({'https': proxy}), OfficialRedirects())
    return opener.open(request, timeout=12)


@lru_cache(maxsize=1)
def proxy_candidates():
    from public_proxy import candidates, find_proxies
    verified = find_proxies()
    # Catalog probes identify working CONNECT routes, but a large package can
    # expose different throughput and timeout behavior. Race all candidates
    # while putting verified routes first.
    return list(dict.fromkeys(verified + candidates()))


def race_proxies(transfer, proxies):
    stop = Event()
    finish = Lock()
    error = None

    def attempt(proxy):
        result = transfer(proxy, stop)
        with finish:
            if stop.is_set():
                raise OSError('Download cancelled')
            stop.set()
        return result

    with ThreadPoolExecutor(max_workers=PROXY_WORKERS) as pool:
        futures = [pool.submit(attempt, proxy) for proxy in proxies]
        try:
            for future in as_completed(futures):
                try:
                    return future.result()
                except (OSError, HTTPException, ValueError) as failed:
                    error = failed
        finally:
            stop.set()
            for future in futures:
                future.cancel()
    raise OSError(f'All proxy downloads failed ({len(proxies)} routes): {error}') from error


def fetch(url, transfer):
    official_url(url)
    for attempt in range(1 if PUBLIC_PROXY else 3):
        try:
            return transfer(None, Event())
        except (OSError, HTTPException, ValueError) as error:
            if PUBLIC_PROXY:
                print(f'Direct download failed for {url}: {error}; trying public proxies', flush=True)
                result = race_proxies(transfer, proxy_candidates())
                print(f'Completed via public proxy: {url}', flush=True)
                return result
            if (attempt == 2 or isinstance(error, ValueError)
                    or isinstance(error, HTTPError) and error.code < 500):
                raise
            time.sleep(2 ** attempt)


def response_blocks(response, stop, limit, duration):
    if stop.is_set():
        raise OSError('Download cancelled')
    headers = getattr(response, 'headers', {})
    if getattr(response, 'status', 200) != 200 or headers.get('Content-Range'):
        raise HTTPException('Expected a complete HTTP 200 response')
    length = headers.get('Content-Length')
    deadline = time.monotonic() + duration
    size = 0
    while not stop.is_set():
        block = response.read1(64 * 1024)
        if time.monotonic() > deadline:
            raise TimeoutError('Download exceeded its time limit')
        if not block:
            if length is not None and size != int(length):
                raise OSError('Truncated HTTP response')
            return
        size += len(block)
        if size > limit:
            raise ValueError('Response exceeds download size limit')
        yield block
    raise OSError('Download cancelled')


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
    def transfer(proxy, stop):
        if stop.is_set():
            raise OSError('Download cancelled')
        with open_url(url, proxy) as response:
            content = b''.join(response_blocks(response, stop, 2 * 1024 * 1024, 30))
        links = links_in(content.decode('utf-8-sig'), url)
        if not links:
            raise ValueError('Download catalog contains no links')
        return links

    return fetch(url, transfer)


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


def fetch_package(url, output, expected=None):
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.topsap-download-', dir=target.parent) as directory:
        def transfer(proxy, stop):
            if stop.is_set():
                raise OSError('Download cancelled')
            digest, size = hashlib.sha256(), 0
            temporary = None
            try:
                with (open_url(url, proxy) as response,
                      tempfile.NamedTemporaryFile(dir=directory, delete=False) as stream):
                    temporary = Path(stream.name)
                    limit = expected['size'] if expected else MAX_PACKAGE_BYTES
                    for block in response_blocks(response, stop, limit, 15 * 60):
                        size += len(block)
                        digest.update(block)
                        stream.write(block)
                result = {'sha256': digest.hexdigest(), 'size': size}
                if not size:
                    raise ValueError('Empty package download')
                if expected and any(result[key] != expected[key] for key in result):
                    raise PackageMismatch('Downloaded package does not match the committed lock: '
                                          + json.dumps(result, sort_keys=True))
                completed, temporary = temporary, None
                return completed, result
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)

        temporary, result = fetch(url, transfer)
        os.replace(temporary, target)
        return result


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
