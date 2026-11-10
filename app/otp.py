import base64
import hashlib
import hmac
import struct
import time
from config import settings


def load_config(credentials):
    values = settings()
    config = dict(version=1, gateway=values['VPN_HOST'], account=values['VPN_ACCOUNT'],
                  secret=values['VPN_TOTP_SECRET'], algorithm='SHA1', digits=6, period=30)
    if (config.get("version") != 1
            or config.get("gateway") != credentials["VPN_HOST"]
            or config.get("account") != credentials["VPN_ACCOUNT"]):
        raise ValueError("OTP configuration does not match the VPN account and gateway")
    if (config.get("algorithm") != "SHA1"
            or config.get("digits") != 6
            or config.get("period") != 30):
        raise ValueError("Unsupported OTP configuration")
    try:
        if len(decode_secret(config["secret"])) < 10:
            raise ValueError
    except (KeyError, ValueError, TypeError):
        raise ValueError("Invalid OTP secret") from None
    return config


def decode_secret(secret):
    value = secret.strip().upper().rstrip("=")
    return base64.b32decode(value + "=" * (-len(value) % 8))


def totp(secret, timestamp=None, digits=6, period=30):
    timestamp = time.time() if timestamp is None else timestamp
    counter = struct.pack(">Q", int(timestamp // period))
    digest = hmac.new(decode_secret(secret), counter, hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return str(value % (10 ** digits)).zfill(digits)
