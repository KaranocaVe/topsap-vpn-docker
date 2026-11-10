import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time

from config import settings
from network import command, gateway_firewall, install_firewall, probe, tunnel_for

APP = pathlib.Path('/opt/apps/cn.com.topvpn/files')
RUNTIME = pathlib.Path('/run/topsap')
PROGRAMS = pathlib.Path(__file__).parent
STOPPING = False


class AuthenticationError(RuntimeError):
    pass


def stopping(signum, frame):
    global STOPPING
    STOPPING = True


def log(message):
    print(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), message, flush=True)


def status(state, **extra):
    target = RUNTIME / 'status.json'
    temp = target.with_suffix('.tmp')
    temp.write_text(json.dumps(dict(state=state, updated=time.time(), **extra)))
    temp.replace(target)


def sleep(seconds):
    deadline = time.monotonic() + seconds
    while not STOPPING and time.monotonic() < deadline:
        time.sleep(0.2)


def launch(args, **kwargs):
    return subprocess.Popen(args, start_new_session=True, **kwargs)


def terminate(processes):
    for process in reversed(processes):
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 4
    for process in reversed(processes):
        try:
            process.wait(timeout=max(0.05, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            pass
        # The group may still contain Electron descendants after its leader exits.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def wait_until(predicate, timeout, processes):
    deadline = time.monotonic() + timeout
    while not STOPPING and time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError('Required VPN process exited')
        if predicate():
            return
        sleep(0.25)
    raise RuntimeError('VPN startup interrupted or timed out')


def prepare(original_resolver):
    pathlib.Path('/etc/resolv.conf').write_text(original_resolver)
    for path in (pathlib.Path('/opt/apps/cn.com.topvpn'),
                 pathlib.Path('/tmp/topsap-profile'), pathlib.Path('/tmp/TopSAP_ELE')):
        shutil.rmtree(path, ignore_errors=True)
    config = pathlib.Path('/opt/sslvpn/config')
    for path in config.iterdir():
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    subprocess.run(['ipcrm', '--all'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.copytree('/usr/local/lib/topsap-payload/cn.com.topvpn', '/opt/apps/cn.com.topvpn')
    for name in ('vpnclient-sysconfig', 'resinfo-config', 'spa_dateconfig', 'spaconfig', '.sysconfig'):
        (config / name).touch()


def vpn_resolver(config):
    path = pathlib.Path('/etc/resolv.conf')
    desired = f"nameserver {config['VPN_DNS']}\noptions timeout:2 attempts:2\n"
    if path.read_text() != desired:
        path.write_text(desired)


def run_cycle(config, original_resolver, on_ready):
    processes = []
    proxy = None
    try:
        status('connecting')
        prepare(original_resolver)
        gateway_firewall(config['VPN_HOST'])
        devnull = dict(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        backend_env = dict(os.environ, LD_LIBRARY_PATH=str(APP))
        backend = launch([str(APP / 'sv_websrv')], cwd=APP, env=backend_env, **devnull)
        processes.append(backend)
        wait_until(lambda: pathlib.Path('/tmp/TopSAP_ELE/.BUFF').is_dir(), 15, processes)
        xvfb = launch(['Xvfb', ':0', '-screen', '0', '1280x800x24', '-nolisten', 'tcp', '-noreset'], **devnull)
        processes.append(xvfb)
        wait_until(lambda: pathlib.Path('/tmp/.X11-unix/X0').exists(), 10, processes)
        electron = launch([str(APP / 'ele/TopSAP'), '--no-sandbox', '--disable-dev-shm-usage',
                           '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=9222',
                           '--user-data-dir=/tmp/topsap-profile'], cwd=APP / 'ele', env=backend_env, **devnull)
        processes.append(electron)
        if config.get('DEBUG_DESKTOP', '0') == '1':
            processes.append(launch(['openbox'], **devnull))
            processes.append(launch(['x11vnc', '-display', ':0', '-localhost', '-forever',
                                     '-shared', '-nopw', '-rfbport', '5900'], **devnull))
            processes.append(launch(['websockify', '--web=/usr/share/novnc',
                                     '0.0.0.0:6080', '127.0.0.1:5900'], **devnull))
        login = launch([sys.executable, str(PROGRAMS / 'vpn_login.py')])
        processes.append(login)
        wait_until(lambda: login.poll() is not None, config['LOGIN_TIMEOUT'] + 100, processes[:-1])
        if login.returncode != 0:
            raise AuthenticationError('VPN authentication did not complete')
        processes.remove(login)
        wait_until(lambda: tunnel_for(config['HEALTHCHECK_HOST']) is not None
                   and tunnel_for(config['VPN_DNS']) is not None, 30, processes)
        vpn_resolver(config)
        proxy = launch(['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups',
                        '--no-new-privs',
                        'microsocks', '-i', '0.0.0.0', '-p', '1080'], **devnull)
        processes.append(proxy)
        wait_until(lambda: proxy.poll() is None, 2, processes)
        sleep(0.5)
        probe(config['HEALTHCHECK_HOST'], config['HEALTHCHECK_PORT'])
        status('ready', interface=tunnel_for(config['HEALTHCHECK_HOST']))
        on_ready()
        log('VPN ready; SOCKS5 listening on port 1080 with TUN-only outbound access.')
        failures = 0
        while not STOPPING:
            if any(p.poll() is not None for p in processes):
                raise RuntimeError('Required VPN or proxy process exited')
            try:
                vpn_resolver(config)
                if not tunnel_for(config['HEALTHCHECK_HOST']):
                    raise RuntimeError('TUN route disappeared')
                probe(config['HEALTHCHECK_HOST'], config['HEALTHCHECK_PORT'])
                failures = 0
                status('ready', interface=tunnel_for(config['HEALTHCHECK_HOST']))
            except Exception:
                failures += 1
                status('degraded', failures=failures)
                if failures >= 3 or not tunnel_for(config['HEALTHCHECK_HOST']):
                    raise RuntimeError('VPN connectivity check failed') from None
            sleep(10)
    finally:
        status('stopping' if STOPPING else 'reconnecting')
        # Proxy is the last process, so stop it before tearing down the tunnel.
        terminate(processes)
        links = json.loads(command('ip', '-d', '-j', 'link', 'show'))
        for link in links:
            if link.get('linkinfo', {}).get('info_kind') == 'tun':
                subprocess.run(['ip', 'link', 'delete', link['ifname']], capture_output=True)


def main():
    os.umask(0o077)
    for name in ('/run/topsap', '/opt/apps', '/opt/sslvpn/config', os.environ['HOME'], '/dev/net'):
        pathlib.Path(name).mkdir(parents=True, exist_ok=True)
    config = settings()
    # Docker Desktop bind-file modes alone do not enforce Linux UID isolation.
    # The parent is native tmpfs, so traversal is enforceably root-only.
    pathlib.Path('/run/secrets').chmod(0o700)
    if not pathlib.Path('/dev/net/tun').exists():
        os.mknod('/dev/net/tun', 0o20600, os.makedev(10, 200))
    install_firewall()
    original_resolver = 'nameserver 127.0.0.11\noptions timeout:2 attempts:2\n'
    failures = 0
    authentication_failures = 0
    def reset_authentication_failures():
        nonlocal authentication_failures
        authentication_failures = 0

    while not STOPPING:
        started = time.monotonic()
        try:
            run_cycle(config, original_resolver, reset_authentication_failures)
        except AuthenticationError:
            authentication_failures += 1
            if authentication_failures >= config['LOGIN_FAILURE_LIMIT']:
                status('needs_attention', reason='authentication_failure_limit')
                log('Authentication failure limit reached; correct .env and recreate the service.')
                while not STOPPING:
                    sleep(5)
                break
            log('VPN authentication failed; retrying within the configured attempt limit.')
        except Exception as error:
            # Exception messages never include credentials or backend replies.
            log(f'VPN session ended ({type(error).__name__}); reconnecting.')
        if STOPPING:
            break
        failures = 0 if time.monotonic() - started > 300 else failures + 1
        delay = min(120, 10 * 2 ** min(failures - 1, 4))
        status('reconnecting', retry_seconds=delay)
        sleep(delay)
    status('stopped')
    log('VPN proxy stopped.')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, stopping)
    signal.signal(signal.SIGINT, stopping)
    try:
        main()
    except Exception as error:
        log(f'Service initialization failed ({type(error).__name__}).')
        sys.exit(1)
