"""Small HTTP GET for enrich (no extra deps)."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request

UA = "ReDiscover/0.4.1 (+https://github.com/wbharris/ReDiscover)"


def http_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = 25,
) -> tuple[int, str, str]:
    """Return (status, body, error). status 0 means transport failure."""
    hdrs = {"User-Agent": UA, "Accept": "application/json, text/html;q=0.9, */*;q=0.5"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(2_000_000).decode("utf-8", "replace")
            return int(resp.status), body, ""
    except urllib.error.HTTPError as exc:
        body = exc.read(4000).decode("utf-8", "replace") if exc.fp else ""
        return int(exc.code), body, f"HTTP {exc.code}"
    except Exception as exc:
        return 0, "", str(exc)
