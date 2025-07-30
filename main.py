import json
import sys

from main_app.argparser import arg_parser
from main_app.colors import colorize
from main_app.constants import client_headers, sec_headers, headers, information_headers, cache_headers, MAIN_DIR
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

    results = []

    for target in targets:
        if args.port:
            target = append_port(target, args.port)

        response = check_target(target, args)

        if response is None:
            results.append({
                "target": target,
                "error": "Connection Error"
            })
            headers.clear()
            continue

        rUrl = response.geturl()

        print(f"[*] Analyzing headers of {colorize(target, 'info')}")
        print(f"[*] Effective URL: {colorize(rUrl, 'info')}")

        # =============================================================
        # OLD
        # -------------------------------------------------------------
        # hdr_lines = response.info().headers
        # -------------------------------------------------------------

        # NEW (variant 1)
        # -------------------------------------------------------------
        hdr_lines = [f"{k}: {v}" for k, v in response.getheaders()]
        # -------------------------------------------------------------

        # NEW (variant 2)
        # -------------------------------------------------------------
        # hdr_lines = [f"{k}: {v}" for k, v in response.info().items()]
        # =============================================================

        parse_headers(hdr_lines)

        safe = 0
        unsafe = 0
        security_headers_present = []
        security_headers_missing = []
        weak_headers = {}

        for safeh in sec_headers:
            if safeh in headers:
                safe += 1
                security_headers_present.append(safeh)
                if safeh == 'X-XSS-Protection' and headers[safeh] == '0':
                    weak_headers[safeh] = headers[safeh]
                    print(
                        f"[*] Header {colorize(safeh, 'ok')} is present! (Value: {colorize(headers[safeh], 'warning')})")
                else:
                    print(f"[*] Header {colorize(safeh, 'ok')} is present! (Value: {headers[safeh]})")
            else:
                unsafe += 1
                security_headers_missing.append(safeh)
                if safeh == 'Strict-Transport-Security' and not is_https(rUrl):
                    unsafe -= 1
                    continue
                print(f"[!] Missing security header: {colorize(safeh, sec_headers[safeh])}")

        info_disclosure = {}
        if args.information:
            found = False
            for h in information_headers:
                if h in headers:
                    found = True
                    info_disclosure[h] = headers[h]
                    print(f"[!] Possible info disclosure: {colorize(h, 'warning')} = {headers[h]}")
            if not found:
                print("[*] No information disclosure headers detected")

        cache_headers_dict = {}
        if args.cache_control:
            found = False
            for h in cache_headers:
                if h in headers:
                    found = True
                    cache_headers_dict[h] = headers[h]
                    print(f"[!] Cache header {colorize(h, 'info')} = {headers[h]}")
            if not found:
                print("[*] No caching headers detected")

        report(rUrl, safe, unsafe)

        header_score = {
            "total_checked": len(sec_headers),
            "present": safe,
            "missing": unsafe,
            "weak": len(weak_headers)
        }

        result = {
            "target": target,
            "effective_url": rUrl,
            "security_headers_present": security_headers_present,
            "security_headers_missing": security_headers_missing,
            "weak_headers": weak_headers,
            "information_disclosure": info_disclosure,
            "cache_headers": cache_headers_dict,
            "header_score": header_score
        }
        results.append(result)

        headers.clear()

    OUTPUT_JSON = MAIN_DIR / args.output

    if not results:
        results = {"message": "Nothing to show by shcheck"}
    with OUTPUT_JSON.open('w') as jf:
        json.dump(results, jf, indent=2)

    print("[+] Results written to results.json")


if __name__ == '__main__':
    main()
