#!/usr/bin/python3
import json
import os
import subprocess
import sys
import time
import urllib.request

import websocket

from common import read_credentials
from otp import load_config, totp
from config import settings


DEBUG_ENDPOINT = "http://127.0.0.1:9222/json/list"


def get_page_target():
    with urllib.request.urlopen(DEBUG_ENDPOINT, timeout=2) as response:
        targets = json.load(response)
    return next((target for target in targets if target.get("type") == "page"), None)


def evaluate(ws, expression, command_id=1):
    ws.send(
        json.dumps(
            {
                "id": command_id,
                "method": "Runtime.evaluate",
                "params": {"expression": expression, "returnByValue": True},
            }
        )
    )
    while True:
        result = json.loads(ws.recv())
        if result.get("id") == command_id:
            if "error" in result:
                raise RuntimeError("DevTools evaluation failed")
            if "exceptionDetails" in result["result"]:
                raise RuntimeError("TopSAP page evaluation failed")
            return result["result"]["result"].get("value")


def wait_for_form():
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            target = get_page_target()
            if target:
                return target
        except Exception:
            pass
        time.sleep(1)
    raise TimeoutError("TopSAP login page did not become available")


def fill_and_submit(credentials):
    target = wait_for_form()
    ws = websocket.create_connection(
        target["webSocketDebuggerUrl"], timeout=10, suppress_origin=True
    )
    try:
        for attempt in range(90):
            ready = evaluate(
                ws,
                "Boolean(document.getElementById('addr') && "
                "document.getElementById('name_1') && "
                "document.getElementById('pwd_1') && "
                "document.getElementById('submitLogin') && "
                "typeof login === 'object' && "
                "typeof getCookie === 'function' && "
                "getCookie('keepClientSystemConfig') && "
                "!document.getElementById('page_init').classList.contains('in'))",
                command_id=attempt + 1,
            )
            if ready:
                break
            time.sleep(1)
        else:
            raise TimeoutError("TopSAP login form did not initialize")

        payload = json.dumps(
            [
                credentials["VPN_HOST"],
                credentials["VPN_ACCOUNT"],
                credentials["VPN_PASSWD"],
            ],
            ensure_ascii=True,
        )
        expression = (
            "(() => { const [host, account, password] = "
            + payload
            + "; document.getElementById('addr').value = host; "
            + "login.from_connect_flag = 0; "
            + "document.getElementById('name_1').value = account; "
            + "document.getElementById('pwd_1').value = password; "
            + "const remember = document.getElementById('remember_pwd'); "
            + "if (remember) remember.setAttribute('data-value', 'off'); "
            + "const auto = document.getElementById('auto_login'); "
            + "if (auto) auto.setAttribute('data-value', 'off'); "
            + "document.getElementById('submitLogin').click(); return true; })()"
        )
        if not evaluate(ws, expression, command_id=100):
            raise RuntimeError("TopSAP refused to submit login")
    finally:
        ws.close()


def submit_otp_if_requested(config):
    target = get_page_target()
    if not target:
        return False
    ws = websocket.create_connection(
        target["webSocketDebuggerUrl"], timeout=5, suppress_origin=True
    )
    try:
        state = evaluate(ws, """(() => {
            const visible = id => {const e=document.getElementById(id);
                return Boolean(e && e.getClientRects().length &&
                    getComputedStyle(e).visibility !== 'hidden');};
            const active = id => visible(id) && document.getElementById(id).classList.contains('in');
            if (typeof login !== 'object' || !login.addrArr || !login.addrArr[0]) return null;
            if (active('google_windows')) return {mode:0,
                enrollment:visible('google_qrcode'),
                offered:document.getElementById('google_msg_show').textContent.trim()};
            if (active('FreeOtp_windows') && visible('FreeOtp_verify'))
                return {mode:1,enrollment:false};
            return null;
        })()""")
        if not state:
            return False
        if state["enrollment"] and state.get("offered") != config["secret"]:
            raise ValueError("Gateway enrollment secret differs from the saved OTP file")
        remaining = config["period"] - time.time() % config["period"]
        if remaining < 6:
            time.sleep(remaining + 0.5)
        payload = json.dumps([state["mode"], totp(config["secret"])])
        submitted = evaluate(ws, """(() => {
            const [mode, token] = """ + payload + """;
            const input=document.getElementById(mode ? 'freeotp_code_value' : 'google_code_value');
            if (!input || typeof login !== 'object') return false;
            if (!mode) login.google_next_event();
            input.value=token;
            login.submit_google_code(mode);
            return true;
        })()""", command_id=2)
        if submitted:
            print("Submitted a locally generated OTP through the client authentication flow.", flush=True)
        return bool(submitted)
    finally:
        ws.close()


def wait_for_tunnel(timeout=900, otp_config=None):
    deadline = time.monotonic() + timeout
    otp_submitted = False
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(
                ["ip", "-d", "-j", "link", "show"],
                check=True, capture_output=True, text=True,
            )
            for link in json.loads(result.stdout):
                if (link.get("linkinfo", {}).get("info_kind") == "tun"
                        and "UP" in link.get("flags", [])):
                    # Larger packets stalled connections on this VPN path.
                    # Use a conservative tunnel MTU to avoid fragmentation issues.
                    subprocess.run(
                        ["ip", "link", "set", "dev", link["ifname"], "mtu", str(settings()['VPN_MTU'])],
                        check=True, capture_output=True, text=True,
                    )
                    return link["ifname"]
        except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
            pass
        if otp_config and not otp_submitted:
            try:
                otp_submitted = submit_otp_if_requested(otp_config)
            except (OSError, websocket.WebSocketException):
                pass
        time.sleep(2)
    return None


def main():
    credentials = read_credentials()
    otp_config = load_config(credentials)
    print("Filling the TopSAP login form and submitting the supplied credentials.", flush=True)
    fill_and_submit(credentials)
    print("Login submitted; waiting for an active VPN tunnel.", flush=True)
    tunnel = wait_for_tunnel(timeout=settings()['LOGIN_TIMEOUT'], otp_config=otp_config)
    if not tunnel:
        print("VPN login timed out before a TUN interface appeared.", flush=True)
        return 1
    print(f"VPN tunnel is active on {tunnel}.", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"VPN setup failed ({type(error).__name__}).", file=sys.stderr, flush=True)
        sys.exit(1)
