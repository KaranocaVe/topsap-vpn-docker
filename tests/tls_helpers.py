from contextlib import contextmanager
from dataclasses import dataclass
import ssl
import subprocess
import tempfile
from pathlib import Path


@dataclass(frozen=True)
class TLSCertificates:
    cert_path: Path
    key_path: Path

    @property
    def cert_pem(self):
        return self.cert_path.read_text(encoding='utf-8')

    @property
    def key_pem(self):
        return self.key_path.read_text(encoding='utf-8')

    def trusted_client_context(self):
        return ssl.create_default_context(cafile=str(self.cert_path))


@contextmanager
def temporary_tls_certificates():
    with tempfile.TemporaryDirectory(prefix='topsap-test-tls-') as directory:
        cert_path = Path(directory) / 'server-cert.pem'
        key_path = Path(directory) / 'server-key.pem'
        subprocess.run(
            [
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(key_path), '-out', str(cert_path), '-days', '1',
                '-sha256', '-subj', '/CN=localhost',
                '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
            ],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        yield TLSCertificates(cert_path, key_path)
