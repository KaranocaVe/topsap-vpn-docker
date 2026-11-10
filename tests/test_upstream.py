import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
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
http://user:pass@8.8.8.8:80
http://8.8.8.8:8080
http://8.8.8.8
http://8.8.8.8:
http://8.8.8.8:8080?token=x
file:///tmp/x
'''
        with patch.object(public_proxy, 'urlopen', side_effect=[OSError(), io.BytesIO(raw)]):
            self.assertEqual(public_proxy.candidates(), ['http://8.8.8.8:8080'])

    def test_proxy_json_handles_numeric_ports_and_malformed_rows(self):
        import public_proxy
        raw = json.dumps({'data': [None, {}, {'ip': '8.8.8.8', 'port': 8080},
                                   {'ip': '2001:4860:4860::8888', 'port': '8080'}]}).encode()
        with patch.object(public_proxy, 'urlopen', side_effect=[io.BytesIO(raw), OSError()]):
            self.assertEqual(public_proxy.candidates(),
                             ['http://8.8.8.8:8080', 'http://[2001:4860:4860::8888]:8080'])

    def test_proxy_mismatch_retries_without_accepting_invalid_bytes(self):
        payload = b'complete'
        expected = {'sha256': hashlib.sha256(payload).hexdigest(), 'size': len(payload)}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'package.deb'
            with patch.object(upstream, 'PUBLIC_PROXY', True), \
                    patch.object(upstream, 'open_url', side_effect=[io.BytesIO(b'tampered'), io.BytesIO(payload)]):
                upstream.fetch_package(upstream.SOURCE + 'package.deb', target, expected)
            self.assertEqual(target.read_bytes(), payload)
            with patch.object(upstream, 'PUBLIC_PROXY', True), \
                    patch.object(upstream, 'open_url', side_effect=lambda _: io.BytesIO(b'tampered')):
                with self.assertRaises(upstream.PackageMismatch):
                    upstream.fetch_package(upstream.SOURCE + 'package.deb', target, expected)
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(list(Path(directory).iterdir()), [target])
