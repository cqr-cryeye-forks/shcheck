import argparse


def arg_parser():
    parser = argparse.ArgumentParser(
        description="shcheck — Analyze HTTP security headers from a given target.",
        epilog="Example: python3 main.py --use-get-method --disable-ssl-check https://example.com"
    )

    parser.add_argument(
        "--target",
        help="One or more target URLs to scan (e.g., https://example.com)"
    )

    parser.add_argument(
        "--port", metavar="PORT",
        help="Set a custom port to connect to (e.g., 8443)"
    )

    parser.add_argument(
        "--cookie", metavar="COOKIE_STRING",
        help="Set cookies for the request (e.g., SESSIONID=abc123)"
    )

    parser.add_argument(
        "--add-header", dest="custom_headers",
        metavar="HEADER_STRING", action="append",
        help="Add custom headers (e.g., 'X-Test: value'). Can be used multiple times."
    )

    parser.add_argument(
        "--disable-ssl-check", dest="ssldisabled",
        action="store_true",
        help="Disable SSL/TLS certificate validation"
    )

    parser.add_argument(
        "--use-get-method", dest="useget",
        action="store_true",
        help="Use GET method instead of HEAD"
    )

    parser.add_argument(
        "--information", action="store_true",
        help="Display information disclosure headers (e.g., Server, X-Powered-By)"
    )

    parser.add_argument(
        "--caching", dest="cache_control",
        action="store_true",
        help="Display caching-related headers (e.g., Cache-Control, ETag)"
    )

    parser.add_argument(
        "--proxy", metavar="PROXY_URL",
        help="Use a proxy server for requests (e.g., http://127.0.0.1:8080)"
    )

    parser.add_argument(
        "--hfile", metavar="PATH_TO_FILE",
        help="Read targets from a text file (one per line)"
    )

    return parser.parse_args()
