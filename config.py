"""Small, safe URL probing helper used by the v2 Streamlit workflow.

The original project imported ``config.fuzz`` but the module was missing from
the repository. This implementation keeps the v2 pipeline usable without
requiring a separate fuzzing package or configuration file.
"""

from urllib.parse import urljoin, urlparse

import requests


DEFAULT_PATHS = ("/", "/robots.txt", "/sitemap.xml", "/admin", "/login", "/.well-known/security.txt")


def fuzz(url, paths=DEFAULT_PATHS, timeout=8):
    """Probe common public paths and return human-readable findings.

    This is intentionally a low-volume discovery check, not a destructive
    payload fuzzer. It preserves the result format expected by ``main_v2``.
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return [f"Invalid target URL: {url}"]

    base_url = f"{parsed.scheme}://{parsed.netloc}/"
    findings = []
    session = requests.Session()
    session.headers.update({"User-Agent": "WebGuard/1.0 security discovery"})
    for path in paths:
        target = urljoin(base_url, path)
        try:
            response = session.get(target, timeout=timeout, allow_redirects=False)
            if response.status_code < 400:
                findings.append(f"{path} -> HTTP {response.status_code} (accessible)")
            elif response.status_code not in {404, 410}:
                findings.append(f"{path} -> HTTP {response.status_code}")
        except requests.RequestException as exc:
            findings.append(f"{path} -> request failed: {exc}")
    session.close()
    return findings or ["No common public paths were discovered."]
