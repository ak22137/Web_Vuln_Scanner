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


SECURITY_HEADERS = ("content-security-policy", "x-content-type-options",
                    "strict-transport-security", "x-frame-options")


def verify_finding(target, finding_type, header=None, probe=None):
    """Verify only observations with a safe, deterministic oracle.

    Other legacy tool signals are retained as unverified evidence rather than
    being promoted to confirmed vulnerabilities.
    """
    if finding_type == "xss":
        if isinstance(probe, dict) and probe.get("reflected") and probe.get("encoded") is False:
            return {"status": "confirmed", "verified": True, "confidence": "High",
                    "finding_type": finding_type, "evidence": probe}
        return {"status": "inconclusive", "verified": False, "finding_type": finding_type,
                "reason": "A structured XSS probe with context and encoding results is required."}
    if finding_type == "lfi":
        if isinstance(probe, dict) and probe.get("marker_found") and probe.get("baseline_changed"):
            return {"status": "confirmed", "verified": True, "confidence": "High",
                    "finding_type": finding_type, "evidence": probe}
        return {"status": "inconclusive", "verified": False, "finding_type": finding_type,
                "reason": "A structured LFI probe with a controlled marker is required."}
    if finding_type != "missing_security_header":
        return {"status": "inconclusive", "verified": False,
                "reason": "No deterministic verifier registered for this detector."}
    if header not in SECURITY_HEADERS:
        return {"status": "inconclusive", "verified": False,
                "reason": "An exact security header is required for verification."}
    url = target if str(target).startswith(("http://", "https://")) else f"http://{target}"
    try:
        request = Request(url, method="GET", headers={"User-Agent": "WebGuard-Verifier/1.0"})
        with urlopen(request, timeout=10) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            present = header in headers
            return {"status": "not_detected" if present else "confirmed",
                    "verified": not present, "confidence": "High",
                    "finding_type": finding_type,
                    "evidence": {"url": url, "method": "GET", "status_code": response.status,
                                 "header_tested": header, "present": present,
                                 "header_value": headers.get(header)}}
    except (OSError, URLError, ValueError) as error:
        return {"status": "inconclusive", "verified": False,
                "reason": f"Verification request failed: {error}"}
