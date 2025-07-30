import socket
import ssl

from main_app.constants import headers
import urllib.request as urlreq
import urllib.error as urlerror


def parse_headers(hdrs):
    map(lambda header: headers.update((header.rstrip().split(':', 1),)), hdrs)


def append_port(target, port):
    return target[:-1] + ':' + port + '/' \
        if target[-1:] == '/' \
        else target + ':' + port + '/'


def set_proxy(proxy):
    if proxy is None:
        return
    proxyhnd = urlreq.ProxyHandler({
        'http':  proxy,
        'https': proxy
    })
    opener = urlreq.build_opener(proxyhnd)
    urlreq.install_opener(opener)


def get_unsafe_context():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def normalize(target):
    try:
        if socket.inet_aton(target):
            target = 'http://' + target
    except (ValueError, socket.error):
        pass
    finally:
        return target