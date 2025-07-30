# main_app/func_2.py
import urllib.request as urlreq

from main_app.colors import colorize
from main_app.constants import client_headers
from main_app.func_1 import normalize, set_proxy, get_unsafe_context


def check_target(target, options):
    ssldisabled = options.ssldisabled
    useget = options.useget
    proxy = options.proxy

    target = normalize(target)

    try:
        # =====================================================================
        # OLD
        # ---------------------------------------------------------------------
        # request = urlreq.Request(target, headers=client_headers)
        # method = 'GET' if useget else 'HEAD' # Set method
        # request.get_method = lambda: method
        # ---------------------------------------------------------------------

        # NEW
        # ---------------------------------------------------------------------
        method = 'GET' if useget else 'HEAD'  # Set method
        request = urlreq.Request(target, headers=client_headers, method=method)
        # =====================================================================

        # Set proxy
        set_proxy(proxy)
        # Set certificate validation
        if ssldisabled:
            context = get_unsafe_context()
            response = urlreq.urlopen(request, timeout=10, context=context)
        else:
            response = urlreq.urlopen(request, timeout=10)

        return response

    except Exception:
        return None


def is_https(target):
    """
    Check if target support HTTPS for Strict-Transport-Security
    """
    return target.startswith('https://')


def report(target, safe, unsafe):
    print("-------------------------------------------------------")
    print(f"[!] Headers analyzed for {colorize(target, 'info')}")
    print(f"[+] There are {colorize(str(safe), 'ok')} security headers")
    print(f"[-] There are not {colorize(str(unsafe), 'error')} security headers")
    print()
