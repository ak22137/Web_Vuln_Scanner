"""Central finding-type metadata used by verification and reporting."""

FINDING_CATALOG = {
    "missing_security_header": {
        "category": "Security configuration weakness",
        "remediation": "Configure the missing response security headers at the web server or reverse proxy.",
        "cvss": {"status": "Not Applicable", "reason": "Configuration weakness; exploitability requires application context."},
    },
    "xss": {
        "category": "Cross-site scripting",
        "remediation": "Validate and context-encode untrusted input; add appropriate output encoding and CSP.",
    },
    "lfi": {
        "category": "Local file inclusion",
        "remediation": "Use an allowlist of server-side resources and prevent user-controlled filesystem paths.",
    },
    "unclassified": {
        "category": "RapidScan detection",
        "remediation": "Review the supplied evidence and verify the condition manually.",
    },
}


def metadata_for(finding_type):
    return FINDING_CATALOG.get(finding_type, FINDING_CATALOG["unclassified"])
