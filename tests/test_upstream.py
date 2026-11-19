import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from threading import Event
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import upstream


class UpstreamTests(unittest.TestCase):
    def test_catalog_ignores_comments_and_selects_numeric_versions(self):
        base = upstream.SOURCE
        html = '''<!-- <a href="/TopSAP-99.0_amd64.deb"> -->
        <a href="/TopSAP-3.9_amd64.deb">old</a>
        <a href="/TopSAP-3.10_amd64.deb">new</a>
        <a href="/TopSAP-3.10_arm64.deb">arm</a>
        <a href="https://evil.invalid/TopSAP-999.0_arm64.deb">bad</a>'''
        selected = upstream.choose_packages(upstream.links_in(html, base))
        self.assertEqual(selected['amd64']['version'], '3.10')
        self.assertEqual(selected['arm64']['version'], '3.10')

    def test_missing_architecture_fails(self):
        with self.assertRaises(ValueError):
            upstream.choose_packages([upstream.SOURCE + 'TopSAP-3.10_arm64.deb'])

    def test_update_rejects_rollback_before_download(self):
        record = {'sha256': '0' * 64, 'size': 1}
        packages = {arch: dict(record, architecture=arch, version='3.10',
                              url=upstream.SOURCE + 'TopSAP-3.10_' + arch + '.deb')
                    for arch in upstream.ARCHES}
        older = {arch: dict(entry, version='3.9',
                           url=upstream.SOURCE + 'TopSAP-3.9_' + arch + '.deb')
                 for arch, entry in packages.items()}
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / 'lock.json'
            original = json.dumps({'schema': 1, 'source': upstream.SOURCE, 'packages': packages})
            lock.write_text(original)
            with patch.object(upstream, 'discover', return_value=older), \
                    patch.object(upstream, 'fetch_package') as download:
                with self.assertRaisesRegex(ValueError, 'rollback'):
                    upstream.update(lock)
                download.assert_not_called()
            self.assertEqual(lock.read_text(), original)

    def test_download_origin_is_restricted(self):
        for url in ['http://app.topsec.com.cn/file', 'https://evil.invalid/file',
                    'https://app.topsec.com.cn@evil.invalid/file',
                    'https://app.topsec.com.cn/file?token=x']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                upstream.official_url(url)

    def test_mismatched_download_does_not_replace_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'package.deb'
            target.write_bytes(b'previous')
            with patch.object(upstream, 'open_url', return_value=io.BytesIO(b'tampered')):
                with self.assertRaises(ValueError):
                    upstream.fetch_package(upstream.SOURCE + 'package.deb', target,
                                           {'sha256': '0' * 64, 'size': 8})
            self.assertEqual(target.read_bytes(), b'previous')
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_valid_download_and_lock_architecture_validation(self):
        payload = b'package'
        record = {'sha256': hashlib.sha256(payload).hexdigest(), 'size': len(payload)}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'package.deb'
            with patch.object(upstream, 'open_url', return_value=io.BytesIO(payload)):
                self.assertEqual(upstream.fetch_package(upstream.SOURCE + 'package.deb', target, record), record)
            packages = {arch: dict(record, architecture=arch, version='3.10',
                                  url=upstream.SOURCE + 'TopSAP-3.10_' + arch + '.deb')
                        for arch in upstream.ARCHES}
            lock = Path(directory) / 'lock.json'
            data = {'schema': 1, 'source': upstream.SOURCE, 'packages': packages}
            lock.write_text(json.dumps(data))
            upstream.read_lock(lock)
            data['packages']['arm64']['architecture'] = 'amd64'
            lock.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                upstream.read_lock(lock)


class TransportTests(unittest.TestCase):
    def test_update_rejects_partial_http_response_without_a_pinned_hash(self):
        class Partial(io.BytesIO):
            status = 206
            headers = {'Content-Length': '7', 'Content-Range': 'bytes 0-6/100'}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'package.deb'
            with patch.object(upstream, 'open_url', side_effect=lambda *_: Partial(b'partial')):
                with self.assertRaises(upstream.HTTPException):
                    upstream.fetch_package(upstream.SOURCE + 'package.deb', target)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_interrupted_download_retries_and_cleans_partial_file(self):
        class Broken(io.BytesIO):
            headers = {'Content-Length': '100'}
        payload = b'complete'
        expected = {'sha256': hashlib.sha256(payload).hexdigest(), 'size': len(payload)}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'package.deb'
            target.write_bytes(b'previous')
            with patch.object(upstream, 'open_url', side_effect=[Broken(b'partial'), io.BytesIO(payload)]):
                upstream.fetch_package(upstream.SOURCE + 'package.deb', target, expected)
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_proxy_candidates_exclude_private_and_authenticated_endpoints(self):
        import public_proxy
        raw = b'''http://127.0.0.1:80
http://10.0.0.1:80
http://224.0.0.1:80
http://user:pass@8.8.8.8:80
http://8.8.8.8:8080
8.8.8.8:8080
1.1.1.1:81
http://8.8.8.8
http://8.8.8.8:
http://8.8.8.8:8080?token=x
file:///tmp/x
'''
        with patch.object(public_proxy, 'urlopen', return_value=io.BytesIO(raw)):
            self.assertEqual(public_proxy.source_candidates('text-list'),
                             ['http://8.8.8.8:8080', 'http://1.1.1.1:81'])

    def test_proxy_json_handles_numeric_ports_and_malformed_rows(self):
        import public_proxy
        raw = json.dumps({'data': [None, {}, {'ip': '8.8.8.8', 'port': 8080},
                                   {'ip': '2001:4860:4860::8888', 'port': '8080'}]}).encode()
        with patch.object(public_proxy, 'urlopen', return_value=io.BytesIO(raw)):
            self.assertEqual(public_proxy.source_candidates(public_proxy.GEONODE),
                             ['http://8.8.8.8:8080', 'http://[2001:4860:4860::8888]:8080'])

    def test_proxy_race_cancels_running_download_after_first_success(self):
        slow_started = Event()
        slow_cancelled = Event()

        def transfer(proxy, stop):
            if proxy == 'slow':
                slow_started.set()
                if stop.wait(timeout=5):
                    slow_cancelled.set()
                raise OSError('slow route stopped')
            self.assertTrue(slow_started.wait(timeout=5))
            return 'complete'

        self.assertEqual(upstream.race_proxies(transfer, ['slow', 'fast']), 'complete')
        self.assertTrue(slow_cancelled.is_set())

    def test_proxy_race_discards_invalid_bytes_and_preserves_existing_file_on_failure(self):
        payload = b'complete'
        expected = {'sha256': hashlib.sha256(payload).hexdigest(), 'size': len(payload)}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'package.deb'
            target.write_bytes(b'previous')

            def open_package(url, proxy):
                if proxy is None:
                    raise OSError('direct route failed')
                return io.BytesIO(payload if proxy == 'valid' else b'tampered')

            with patch.object(upstream, 'PUBLIC_PROXY', True), \
                    patch.object(upstream, 'open_url', side_effect=open_package), \
                    patch.object(upstream, 'proxy_candidates', return_value=['invalid']) as candidates:
                with self.assertRaisesRegex(OSError, 'All proxy downloads failed'):
                    upstream.fetch_package(upstream.SOURCE + 'package.deb', target, expected)
                self.assertEqual(target.read_bytes(), b'previous')
                candidates.return_value = ['invalid', 'valid']
                self.assertEqual(upstream.fetch_package(upstream.SOURCE + 'package.deb', target, expected),
                                 expected)
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(list(Path(directory).iterdir()), [target])
