from config import settings


def read_credentials():
    values = settings()
    return {key: values[key] for key in ('VPN_HOST', 'VPN_ACCOUNT', 'VPN_PASSWD')}
