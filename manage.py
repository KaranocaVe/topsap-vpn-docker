#!/usr/bin/env python3
"""Manage the TopSAP VPN SOCKS5 service."""
import argparse
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'app'))
from config import settings


def load():
    path = ROOT / '.env'
    if not path.is_file():
        raise ValueError('Create .env from .env.example first')
    path.chmod(0o600)
    os.environ['TOPSAP_ENV_FILE'] = str(path)
    values = settings()
    values['SOCKS_PORT'] = int(values.get('SOCKS_PORT', '1080'))
    if not 1 <= values['SOCKS_PORT'] <= 65535:
        raise ValueError('Invalid .env setting: SOCKS_PORT')
    if values['SOCKS_TLS'] == '1':
        for key, default in (('SOCKS_TLS_CERT_FILE', 'runtime/tls/server.crt'),
                             ('SOCKS_TLS_KEY_FILE', 'runtime/tls/server.key')):
            path = Path(values.get(key, default)).expanduser()
            values[key] = str((ROOT / path).resolve())
    if values.get('DEBUG_DESKTOP', '0') not in ('0', '1'):
        raise ValueError('DEBUG_DESKTOP must be 0 or 1')
    image = values.get('TOPSAP_IMAGE', 'ghcr.io/karanocave/topsap-vpn-docker:latest')
    if not re.fullmatch(r'[a-z0-9][a-z0-9._/:@-]*', image):
        raise ValueError('Invalid .env setting: TOPSAP_IMAGE')
    values['TOPSAP_IMAGE'] = image
    return values


def compose(values, *args, capture=False):
    # Only nonsecret deployment settings enter Compose's environment.
    env = dict(os.environ, SOCKS_PORT=str(values['SOCKS_PORT']),
               SOCKS_BIND=values['SOCKS_BIND'],
               SOCKS_TLS=values['SOCKS_TLS'],
               TOPSAP_IMAGE=values['TOPSAP_IMAGE'])
    cmd = ['docker', 'compose', '--project-directory', str(ROOT),
           '--env-file', os.devnull, '-f', str(ROOT / 'compose.yaml')]
    if values['SOCKS_TLS'] == '1':
        env.update({key: values[key] for key in ('SOCKS_TLS_CERT_FILE', 'SOCKS_TLS_KEY_FILE')})
    if values.get('DEBUG_DESKTOP', '0') == '1':
        cmd += ['-f', str(ROOT / 'compose.debug.yaml')]
    return subprocess.run(cmd + list(args), env=env, check=True,
                          capture_output=capture, text=True)


def prepare(values):
    if values['SOCKS_TLS'] == '1':
        cert, key = (Path(values[name]) for name in ('SOCKS_TLS_CERT_FILE', 'SOCKS_TLS_KEY_FILE'))
        for setting, path in (('SOCKS_TLS_CERT_FILE', cert), ('SOCKS_TLS_KEY_FILE', key)):
            if not path.is_file():
                raise ValueError(f'{setting} must point to a file: {path}')
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert, key, password='')
        except OSError as error:
            raise ValueError(f'Cannot load SOCKS TLS certificate and key ({cert}, {key}): {error}') from None
    runtime = ROOT / 'runtime'
    runtime.mkdir(exist_ok=True)
    # Bind just this public resolver file; the rest of the rootfs stays read-only.
    resolver = runtime / 'resolv.conf'
    if not resolver.exists():
        resolver.write_text('nameserver 127.0.0.11\noptions timeout:2 attempts:2\n')
    resolver.chmod(0o644)


def wait_healthy(values, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = compose(values, 'ps', '--all', '--format', 'json', capture=True).stdout.strip()
        rows = [json.loads(line) for line in result.splitlines() if line]
        if rows and rows[0].get('Health') == 'healthy':
            address = values['SOCKS_BIND']
            if ':' in address:
                address = f'[{address}]'
            print(f"VPN healthy; SOCKS5 listening at {address}:{values['SOCKS_PORT']}")
            return
        if rows and rows[0].get('State') in ('exited', 'dead'):
            raise RuntimeError('VPN container exited; inspect ./manage.py logs')
        time.sleep(2)
    raise RuntimeError('VPN did not become healthy; inspect ./manage.py logs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('up', 'build', 'pull', 'update', 'down', 'restart', 'status',
                                           'logs', 'check'))
    parser.add_argument('--build', action='store_true', help='Build image before up')
    parser.add_argument('--timeout', type=int, default=240, help='Startup wait in seconds')
    args = parser.parse_args()
    values = load()
    if args.action == 'up':
        prepare(values)
        compose(values, 'up', '-d', *(['--build'] if args.build else []))
        wait_healthy(values, args.timeout)
    elif args.action == 'build':
        compose(values, 'build')
    elif args.action == 'pull':
        compose(values, 'pull')
    elif args.action == 'update':
        prepare(values)
        compose(values, 'pull')
        compose(values, 'up', '-d', '--no-build')
        wait_healthy(values, args.timeout)
    elif args.action == 'down':
        compose(values, 'down', '--remove-orphans')
    elif args.action == 'restart':
        prepare(values)
        compose(values, 'up', '-d', '--force-recreate')
        wait_healthy(values, args.timeout)
    elif args.action == 'status':
        compose(values, 'ps', '--all')
    elif args.action == 'logs':
        compose(values, 'logs', '--tail', '100', '-f')
    elif args.action == 'check':
        compose(values, 'exec', '-T', 'vpn', 'python3', '/usr/local/lib/topsap-service/healthcheck.py')
        print('VPN route and SOCKS-to-target check passed.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f'Error: {error}', file=sys.stderr)
        sys.exit(1)
