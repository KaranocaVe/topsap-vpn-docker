#!/usr/bin/env python3
"""Host-side lifecycle and SSH configuration; credentials are never executed."""
import argparse
import json
import os
from pathlib import Path
import re
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
    for key in ('SOCKS_PORT', 'SSH_PORT'):
        values[key] = int(values.get(key, '1080' if key == 'SOCKS_PORT' else '22'))
        if not 1 <= values[key] <= 65535:
            raise ValueError(f'Invalid .env setting: {key}')
    for key in ('SSH_ALIAS', 'SSH_HOST', 'SSH_ACCOUNT'):
        value = values.get(key, '')
        if not re.fullmatch(r'[A-Za-z0-9_.:@-]+', value) or value.startswith('-'):
            raise ValueError(f'Invalid .env setting: {key}')
    if values.get('DEBUG_DESKTOP', '0') not in ('0', '1'):
        raise ValueError('DEBUG_DESKTOP must be 0 or 1')
    if values.get('SSH_HOST_KEY_POLICY', 'accept-new') not in ('accept-new', 'dynamic'):
        raise ValueError('SSH_HOST_KEY_POLICY must be accept-new or dynamic')
    image = values.get('TOPSAP_IMAGE', 'ghcr.io/karanocave/topsap-vpn-docker:latest')
    if not re.fullmatch(r'[a-z0-9][a-z0-9._/:@-]*', image):
        raise ValueError('Invalid .env setting: TOPSAP_IMAGE')
    values['TOPSAP_IMAGE'] = image
    return values


def compose(values, *args, capture=False):
    # Only the nonsecret published port enters Compose's environment.
    env = dict(os.environ, SOCKS_PORT=str(values['SOCKS_PORT']),
               TOPSAP_IMAGE=values['TOPSAP_IMAGE'])
    cmd = ['docker', 'compose', '--project-directory', str(ROOT),
           '--env-file', os.devnull, '-f', str(ROOT / 'compose.yaml')]
    if values.get('DEBUG_DESKTOP', '0') == '1':
        cmd += ['-f', str(ROOT / 'compose.debug.yaml')]
    return subprocess.run(cmd + list(args), env=env, check=True,
                          capture_output=capture, text=True)


def prepare():
    runtime = ROOT / 'runtime'
    runtime.mkdir(exist_ok=True)
    # Bind just this public resolver file; the rest of the rootfs stays read-only.
    resolver = runtime / 'resolv.conf'
    if not resolver.exists():
        resolver.write_text('nameserver 127.0.0.11\noptions timeout:2 attempts:2\n')
    resolver.chmod(0o644)


def ssh_config(values, install=False):
    config = ROOT / 'ssh_config'
    text = (f"Host {values['SSH_ALIAS']}\n"
            f"    HostName {values['SSH_HOST']}\n"
            f"    User {values['SSH_ACCOUNT']}\n"
            f"    Port {values['SSH_PORT']}\n"
            f"    ProxyCommand /usr/bin/nc -X 5 -x 127.0.0.1:{values['SOCKS_PORT']} %h %p\n"
            '    ClearAllForwardings yes\n'
            '    ConnectTimeout 20\n'
            '    ServerAliveInterval 30\n'
            '    ServerAliveCountMax 3\n')
    if values.get('SSH_HOST_KEY_POLICY', 'accept-new') == 'dynamic':
        text += ('    StrictHostKeyChecking no\n'
                 '    UserKnownHostsFile /dev/null\n'
                 '    GlobalKnownHostsFile /dev/null\n'
                 '    UpdateHostKeys no\n'
                 '    LogLevel ERROR\n')
    else:
        text += '    StrictHostKeyChecking accept-new\n'
    config.write_text(text)
    config.chmod(0o600)
    if install:
        directory = Path.home() / '.ssh'
        directory.mkdir(mode=0o700, exist_ok=True)
        target = directory / 'config'
        original = target.read_text() if target.exists() else ''
        quoted = str(config).replace('\\', '\\\\').replace('"', '\"')
        include = f'Include "{quoted}"'
        # Prepend so this alias takes precedence over global Host * defaults.
        lines = [line for line in original.splitlines() if line.strip() != include]
        temp = directory / '.config.topsap.tmp'
        temp.write_text(include + '\n' + '\n'.join(lines) + '\n')
        temp.chmod(0o600)
        temp.replace(target)
    print(f'SSH config ready: {config}')


def wait_healthy(values, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = compose(values, 'ps', '--all', '--format', 'json', capture=True).stdout.strip()
        rows = [json.loads(line) for line in result.splitlines() if line]
        if rows and rows[0].get('Health') == 'healthy':
            print(f"VPN healthy; SOCKS5 at 127.0.0.1:{values['SOCKS_PORT']}")
            return
        if rows and rows[0].get('State') in ('exited', 'dead'):
            raise RuntimeError('VPN container exited; inspect ./manage.py logs')
        time.sleep(2)
    raise RuntimeError('VPN did not become healthy; inspect ./manage.py logs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('up', 'build', 'pull', 'update', 'down', 'restart', 'status',
                                           'logs', 'ssh-config', 'ssh', 'check'))
    parser.add_argument('--build', action='store_true', help='Build image before up')
    parser.add_argument('--install', action='store_true', help='Include generated SSH config in ~/.ssh/config')
    parser.add_argument('--timeout', type=int, default=240, help='Startup wait in seconds')
    args, extra = parser.parse_known_args()
    if extra and args.action != 'ssh':
        parser.error('Unrecognized arguments')
    values = load()
    if args.action == 'up':
        prepare()
        ssh_config(values)
        compose(values, 'up', '-d', *(['--build'] if args.build else []))
        wait_healthy(values, args.timeout)
    elif args.action == 'build':
        compose(values, 'build')
    elif args.action == 'pull':
        compose(values, 'pull')
    elif args.action == 'update':
        prepare()
        compose(values, 'pull')
        compose(values, 'up', '-d', '--no-build')
        wait_healthy(values, args.timeout)
    elif args.action == 'down':
        compose(values, 'down', '--remove-orphans')
    elif args.action == 'restart':
        prepare()
        compose(values, 'up', '-d', '--force-recreate')
        wait_healthy(values, args.timeout)
    elif args.action == 'status':
        compose(values, 'ps', '--all')
    elif args.action == 'logs':
        compose(values, 'logs', '--tail', '100', '-f')
    elif args.action == 'ssh-config':
        ssh_config(values, args.install)
    elif args.action == 'check':
        compose(values, 'exec', '-T', 'vpn', 'python3', '/usr/local/lib/topsap-service/healthcheck.py')
        print('VPN route and SOCKS-to-target check passed.')
    elif args.action == 'ssh':
        ssh_config(values)
        extra = extra[1:] if extra[:1] == ['--'] else extra
        os.execv('/usr/bin/ssh', ['ssh', '-F', str(ROOT / 'ssh_config'), values['SSH_ALIAS'], *extra])


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f'Error: {error}', file=sys.stderr)
        sys.exit(1)
