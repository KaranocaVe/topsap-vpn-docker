import ipaddress
import os
import pathlib
import re
import shlex


def read_env(path):
    values = {}
    for number, raw in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        key = key.strip()
        if not sep or not re.fullmatch(r'[A-Z][A-Z0-9_]*', key) or key in values:
            raise ValueError(f'Invalid or duplicate .env key on line {number}')
        lexer = shlex.shlex(value, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = '#'
        tokens = list(lexer)
        if len(tokens) > 1:
            raise ValueError(f'Quote .env values containing spaces on line {number}')
        values[key] = tokens[0] if tokens else ''
    return values


def settings():
    values = read_env(os.environ.get('TOPSAP_ENV_FILE', '/run/secrets/topsap.env'))
    for key in ('VPN_HOST', 'VPN_ACCOUNT', 'VPN_PASSWD', 'VPN_TOTP_SECRET',
                'VPN_DNS', 'HEALTHCHECK_HOST'):
        if not values.get(key):
            raise ValueError(f'Missing .env setting: {key}')
    for key in ('VPN_DNS', 'HEALTHCHECK_HOST'):
        ipaddress.ip_address(values[key])
    for key, default, low, high in (('HEALTHCHECK_PORT', '22', 1, 65535),
                                   ('VPN_MTU', '1280', 1280, 1500),
                                   ('LOGIN_FAILURE_LIMIT', '3', 1, 10),
                                   ('LOGIN_TIMEOUT', '120', 30, 900)):
        values[key] = int(values.get(key, default))
        if not low <= values[key] <= high:
            raise ValueError(f'Invalid .env setting: {key}')
    return values
