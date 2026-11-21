import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import manage
from tls_helpers import temporary_tls_certificates


BASE_ENV = """VPN_HOST=vpn.example.com:443
VPN_ACCOUNT=user
VPN_PASSWD=password
VPN_TOTP_SECRET=TESTSEED
VPN_DNS=10.0.0.53
HEALTHCHECK_HOST=10.0.0.10
SOCKS_USERNAME=alice
SOCKS_PASSWORD=secret
"""


class ManageBindTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / ".env").write_text(BASE_ENV)

    def load_with_env(self, extra=""):
        (self.root / ".env").write_text(BASE_ENV + extra)
        with patch.object(manage, "ROOT", self.root), patch.dict(
                os.environ, {"HOME": str(self.root / "home")}, clear=True):
            return manage.load()

    def test_defaults_to_loopback_without_tls(self):
        values = self.load_with_env()
        self.assertEqual(values["SOCKS_BIND"], "127.0.0.1")
        self.assertEqual(values["SOCKS_TLS"], "0")

    def test_non_loopback_ipv4_requires_tls(self):
        values = self.load_with_env("SOCKS_BIND=0.0.0.0\nSOCKS_TLS=1\nSOCKS_TLS_SERVER_NAME=proxy.example.com\n")
        self.assertEqual(values["SOCKS_BIND"], "0.0.0.0")

    def test_ipv6_literal_is_normalized_and_requires_tls_when_public(self):
        values = self.load_with_env(
            "SOCKS_BIND=2001:0db8:0:0:0:0:0:1\nSOCKS_TLS=1\n"
            "SOCKS_TLS_SERVER_NAME=proxy.example.com\n")
        self.assertEqual(values["SOCKS_BIND"], "2001:db8::1")

    def test_loopback_ipv6_is_allowed_without_tls(self):
        values = self.load_with_env("SOCKS_BIND=::1\n")
        self.assertEqual(values["SOCKS_BIND"], "::1")

    def test_invalid_bind_address_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "SOCKS_BIND"):
            self.load_with_env("SOCKS_BIND=not-an-ip\n")

    def test_non_loopback_bind_without_tls_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "SOCKS_TLS"):
            self.load_with_env("SOCKS_BIND=0.0.0.0\n")

    def test_tls_requires_server_name(self):
        with self.assertRaisesRegex(ValueError, "SOCKS_TLS_SERVER_NAME"):
            self.load_with_env("SOCKS_TLS=1\n")

    def test_tls_setting_must_be_zero_or_one(self):
        with self.assertRaisesRegex(ValueError, "SOCKS_TLS"):
            self.load_with_env("SOCKS_TLS=2\n")

    def test_tls_paths_resolve_from_repository_root(self):
        values = self.load_with_env(
            "SOCKS_TLS=1\nSOCKS_TLS_SERVER_NAME=proxy.example.com\n"
            "SOCKS_TLS_CERT_FILE=runtime/certs/server.crt\n"
            "SOCKS_TLS_KEY_FILE=~/private/server.key\n")
        self.assertEqual(values["SOCKS_TLS_CERT_FILE"], str((self.root / "runtime/certs/server.crt").resolve()))
        self.assertEqual(values["SOCKS_TLS_KEY_FILE"], str((self.root / "home/private/server.key").resolve()))

    def test_tls_defaults_resolve_under_repository_root(self):
        values = self.load_with_env("SOCKS_TLS=1\nSOCKS_TLS_SERVER_NAME=proxy.example.com\n")
        self.assertEqual(values["SOCKS_TLS_CERT_FILE"], str((self.root / "runtime/tls/server.crt").resolve()))
        self.assertEqual(values["SOCKS_TLS_KEY_FILE"], str((self.root / "runtime/tls/server.key").resolve()))

    def test_compose_passes_only_nonsecret_bind_settings(self):
        values = {
            "SOCKS_BIND": "0.0.0.0",
            "SOCKS_PORT": 1080,
            "SOCKS_TLS": "1",
            "SOCKS_TLS_CERT_FILE": "/certs/server.crt",
            "SOCKS_TLS_KEY_FILE": "/certs/server.key",
            "TOPSAP_IMAGE": "ghcr.io/example/topsap:test",
            "SOCKS_USERNAME": "alice",
            "SOCKS_PASSWORD": "secret",
            "VPN_ACCOUNT": "user",
            "VPN_PASSWD": "password",
        }
        with patch.object(manage, "ROOT", self.root), patch.dict(
                manage.os.environ, {}, clear=True), patch.object(manage.subprocess, "run") as run:
            manage.compose(values, "config")

        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["SOCKS_BIND"], "0.0.0.0")
        self.assertEqual(environment["SOCKS_PORT"], "1080")
        self.assertEqual(environment["TOPSAP_IMAGE"], values["TOPSAP_IMAGE"])
        for key in ("VPN_ACCOUNT", "VPN_PASSWD", "SOCKS_USERNAME", "SOCKS_PASSWORD"):
            self.assertNotIn(key, environment)

    def test_compose_passes_tls_selection_and_file_paths(self):
        common = {
            "SOCKS_BIND": "0.0.0.0",
            "SOCKS_PORT": 1080,
            "TOPSAP_IMAGE": "ghcr.io/example/topsap:test",
            "SOCKS_USERNAME": "alice",
            "SOCKS_PASSWORD": "secret",
            "VPN_ACCOUNT": "user",
            "VPN_PASSWD": "password",
        }
        tls_values = dict(common, SOCKS_TLS="1",
                          SOCKS_TLS_CERT_FILE=str(self.root / "runtime/tls/server.crt"),
                          SOCKS_TLS_KEY_FILE=str(self.root / "runtime/tls/server.key"))
        plain_values = dict(common, SOCKS_TLS="0")

        with patch.object(manage, "ROOT", self.root), patch.dict(
                manage.os.environ, {"SOCKS_TLS": "0"}, clear=True), patch.object(manage.subprocess, "run") as run:
            manage.compose(tls_values, "config")
            tls_cmd = run.call_args.args[0]
            tls_env = run.call_args.kwargs["env"]
            manage.compose(plain_values, "config")
            plain_cmd = run.call_args.args[0]
            plain_env = run.call_args.kwargs["env"]

        self.assertEqual(tls_cmd, plain_cmd)
        self.assertEqual(tls_env["SOCKS_TLS"], "1")
        self.assertEqual(tls_env["SOCKS_TLS_CERT_FILE"], tls_values["SOCKS_TLS_CERT_FILE"])
        self.assertEqual(tls_env["SOCKS_TLS_KEY_FILE"], tls_values["SOCKS_TLS_KEY_FILE"])
        self.assertEqual(plain_env["SOCKS_TLS"], "0")
        self.assertNotIn("SOCKS_TLS_CERT_FILE", plain_env)
        self.assertNotIn("SOCKS_TLS_KEY_FILE", plain_env)

    def test_prepare_validates_tls_material_before_writing_runtime_files(self):
        values = self.load_with_env("SOCKS_TLS=1\nSOCKS_TLS_SERVER_NAME=proxy.example.com\n")
        with patch.object(manage, "ROOT", self.root), temporary_tls_certificates() as pair:
            with self.assertRaisesRegex(ValueError, "SOCKS_TLS_CERT_FILE"):
                manage.prepare(values)
            self.assertFalse((self.root / "runtime").exists())

            values["SOCKS_TLS_CERT_FILE"] = str(pair.cert_path)
            values["SOCKS_TLS_KEY_FILE"] = str(pair.cert_path)
            with self.assertRaisesRegex(ValueError, "Cannot load SOCKS TLS certificate and key"):
                manage.prepare(values)
            self.assertFalse((self.root / "runtime").exists())

            values["SOCKS_TLS_KEY_FILE"] = str(pair.key_path)
            manage.prepare(values)
            self.assertTrue((self.root / "runtime/resolv.conf").is_file())

    @unittest.skipUnless(shutil.which("docker"), "Docker CLI is unavailable")
    def test_direct_compose_selects_tls_secrets_from_dotenv(self):
        if subprocess.run(["docker", "compose", "version"], capture_output=True).returncode:
            self.skipTest("Docker Compose is unavailable")
        for name in ("compose.yaml", "compose.socks.yaml"):
            shutil.copyfile(ROOT / name, self.root / name)
        env = {name: value for name, value in os.environ.items()
               if not name.startswith(("COMPOSE_", "SOCKS_"))}
        for mode, tls_targets in (("", set()), ("0", set()), ("1", {"socks-tls.crt", "socks-tls.key"})):
            with self.subTest(mode=mode):
                mode_setting = f"SOCKS_TLS={mode}\n" if mode else ""
                (self.root / ".env").write_text(BASE_ENV + mode_setting)
                result = subprocess.run(["docker", "compose", "config", "--format", "json"],
                                        cwd=self.root, env=env, capture_output=True, text=True, check=True)
                services = json.loads(result.stdout)["services"]
                self.assertEqual(set(services), {"vpn"})
                targets = {secret["target"] for secret in services["vpn"]["secrets"]}
                self.assertEqual(targets, {"topsap.env"} | tls_targets)


if __name__ == "__main__":
    unittest.main()
