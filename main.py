import sys

from main_app.argparser import arg_parser
from main_app.colors import colorize
from main_app.constants import client_headers, sec_headers, headers, information_headers, cache_headers
from main_app.func_1 import append_port, parse_headers
from main_app.func_2 import check_target, is_https, report


def main():
    args = arg_parser()

    if not args.target and not args.hfile:
        print("[!] Error: You must provide either --target or --hfile.")
        sys.exit(1)

    if args.hfile:
        with open(args.hfile) as f:
            targets = f.read().splitlines()
    else:
        targets = [args.target]

    if args.cookie:
        client_headers.update({'Cookie': args.cookie})

    if args.custom_headers:
        for header in args.custom_headers:
            try:
                key, value = header.split(': ', 1)
                client_headers.update({key: value})
            except ValueError:
                print("[!] Header must be in the format 'Key: Value'")
                sys.exit(1)

    for target in targets:
        if args.port:
            target = append_port(target, args.port)

        response = check_target(target, args)
        rUrl = response.geturl()

        print(f"[*] Analyzing headers of {colorize(target, 'info')}")
        print(f"[*] Effective URL: {colorize(rUrl, 'info')}")
        parse_headers(response.info().headers)

        safe = 0
        unsafe = 0

        for safeh in sec_headers:
            if safeh in headers:
                safe += 1
                if safeh == 'X-XSS-Protection' and headers[safeh] == '0':
                    print(f"[*] Header {colorize(safeh, 'ok')} is present! (Value: {colorize(headers[safeh], 'warning')})")
                else:
                    print(f"[*] Header {colorize(safeh, 'ok')} is present! (Value: {headers[safeh]})")
            else:
                unsafe += 1
                if safeh == 'Strict-Transport-Security' and not is_https(rUrl):
                    unsafe -= 1
                    continue
                print(f"[!] Missing security header: {colorize(safeh, sec_headers[safeh])}")

        if args.information:
            found = False
            for h in information_headers:
                if h in headers:
                    found = True
                    print(f"[!] Possible info disclosure: {colorize(h, 'warning')} = {headers[h]}")
            if not found:
                print("[*] No information disclosure headers detected")

        if args.cache_control:
            found = False
            for h in cache_headers:
                if h in headers:
                    found = True
                    print(f"[!] Cache header {colorize(h, 'info')} = {headers[h]}")
            if not found:
                print("[*] No caching headers detected")

        report(rUrl, safe, unsafe)


if __name__ == '__main__':
    main()
