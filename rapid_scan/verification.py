"""Deterministic verification helpers for structured RapidScan findings."""

from urllib.error import URLError
from urllib.request import Request, urlopen


FINDING_TYPE_BY_TEST = {
    "whatweb": "missing_security_header",
    "nmapheaders": "missing_security_header",
    "nikto_headers": "missing_security_header",
    "uniscan_rfi": "lfi",
    "nikto_xss": "xss",
    "xsser": "xss",
}


def finding_type_for_test(test_id):
    return FINDING_TYPE_BY_TEST.get(str(test_id), "unclassified")


def verify_finding(target, finding_type):
    """Verify only observations with a safe, deterministic oracle.

    Other legacy tool signals are retained as unverified evidence rather than
    being promoted to confirmed vulnerabilities.
    """
    if finding_type != "missing_security_header":
        return {"status": "inconclusive", "verified": False,
                "reason": "No deterministic verifier registered for this detector."}
    url = target if str(target).startswith(("http://", "https://")) else f"http://{target}"
    try:
        request = Request(url, method="GET", headers={"User-Agent": "WebGuard-Verifier/1.0"})
        with urlopen(request, timeout=10) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            missing = [header for header in ("content-security-policy", "x-content-type-options",
                                              "strict-transport-security", "x-frame-options") if header not in headers]
            return {"status": "confirmed" if missing else "not_detected",
                    "verified": bool(missing), "confidence": "High" if missing else "High",
                    "finding_type": finding_type,
                    "evidence": {"url": url, "method": "GET", "status_code": response.status,
                                 "missing_headers": missing}}
    except (OSError, URLError, ValueError) as error:
        return {"status": "inconclusive", "verified": False,
                "reason": f"Verification request failed: {error}"}
