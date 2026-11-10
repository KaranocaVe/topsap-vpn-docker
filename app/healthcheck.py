import json
import pathlib
import sys
import time

from config import settings
from network import probe, tunnel_for


def check():
    status = json.loads(pathlib.Path('/run/topsap/status.json').read_text())
    if status.get('state') != 'ready' or time.time() - status['updated'] > 45:
        raise RuntimeError('VPN supervisor is not ready')
    config = settings()
    if not tunnel_for(config['HEALTHCHECK_HOST']):
        raise RuntimeError('Health target is not routed through TUN')
    probe(config['HEALTHCHECK_HOST'], config['HEALTHCHECK_PORT'])


if __name__ == '__main__':
    try:
        check()
    except Exception:
        print('VPN proxy is not ready', file=sys.stderr)
        sys.exit(1)
