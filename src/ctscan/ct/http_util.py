"""httpx client construction and CT request retries."""

from __future__ import annotations

import os
import time
from typing import Any

import httpx


def default_ct_timeout() -> httpx.Timeout:
    return httpx.Timeout(connect=30.0, read=180.0, write=30.0, pool=30.0)


def default_roots_timeout() -> httpx.Timeout:
    """Shorter timeouts for small ``get-roots`` JSON responses."""
    return httpx.Timeout(connect=15.0, read=45.0, write=15.0, pool=15.0)


def build_http_client(
    *,
    trust_env: bool = False,
    proxy: str | None = None,
    timeout: httpx.Timeout | None = None,
) -> httpx.Client:
    """
    Build an httpx client for CT API calls.

    Default trust_env=False avoids picking up HTTP_PROXY/HTTPS_PROXY and
    failing TLS to Google CT through a broken local proxy (UNEXPECTED_EOF).
    """
    kwargs: dict[str, Any] = {
        "timeout": timeout or default_ct_timeout(),
        "follow_redirects": True,
        "trust_env": trust_env,
    }
    if proxy:
        kwargs["proxy"] = proxy
    return httpx.Client(**kwargs)


def request_with_retries(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    retries: int = 3,
    **kwargs: Any,
) -> httpx.Response:
    last: BaseException | None = None
    for attempt in range(retries):
        try:
            resp = client.request(method, url, **kwargs)
            resp.raise_for_status()
            return resp
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout) as exc:
            last = exc
            if attempt < retries - 1:
                time.sleep(1.0 * (attempt + 1))
    assert last is not None
    raise last


def format_connect_error_hint(exc: BaseException) -> str:
    proxy_vars = []
    for key in (
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ):
        val = os.environ.get(key)
        if val:
            proxy_vars.append(f"{key}={val}")
    lines = [
        f"[red]Cannot connect to CT log:[/] {exc}",
        "",
        "Common causes:",
        "  · HTTP(S)_PROXY env vars routing traffic through a proxy that breaks TLS to Google",
        "  · No route to ct.googleapis.com / ct.cloudflare.com",
        "",
        "Try:",
        "  · Default is direct (no env proxy). If you need a proxy: [cyan]--use-env-proxy[/] or [cyan]--proxy URL[/]",
        "  · Or unset proxies: unset HTTPS_PROXY HTTP_PROXY ALL_PROXY",
        "  · Different network / VPN",
    ]
    if proxy_vars:
        lines.insert(4, "  · Detected: " + ", ".join(proxy_vars))
    return "\n".join(lines)
