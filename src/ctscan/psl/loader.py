"""Fetch and cache public_suffix_list.dat; map rules to ICANN vs PRIVATE sections."""

from __future__ import annotations

import time
from pathlib import Path

import httpx

from ctscan.ct.http_util import build_http_client, request_with_retries
from ctscan.storage.db import default_data_dir

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

_CACHE: tuple[float, dict[str, str], Path] | None = None


def psl_cache_path() -> Path:
    p = default_data_dir() / "cache" / "public_suffix_list.dat"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def parse_rule_sections(lines: list[str]) -> dict[str, str]:
    """
    Map each PSL rule (without leading '!') to ``icann`` or ``private``.

    Follows section markers in the official list file.
    """
    section = "unknown"
    rules: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if "===BEGIN ICANN DOMAINS===" in line:
            section = "icann"
            continue
        if "===BEGIN PRIVATE DOMAINS===" in line:
            section = "private"
            continue
        if line.startswith("//"):
            continue
        rule = line.split()[0].lstrip(".").lower()
        if rule.startswith("!"):
            rule = rule[1:]
        if rule:
            rules[rule] = section
    return rules


def _fetch_psl_lines() -> list[str]:
    with build_http_client(trust_env=False) as client:
        resp = request_with_retries(client, "GET", PSL_URL)
        return resp.text.splitlines()


def load_psl(*, force_refresh: bool = False, max_age_hours: float = 24.0) -> tuple[dict[str, str], Path]:
    """
    Return (rule -> section, path to .dat used).

    Uses disk cache under ~/.ctscan/cache/; refreshes from PSL_URL when stale.
    """
    global _CACHE
    path = psl_cache_path()
    now = time.time()
    if not force_refresh and path.is_file():
        age_h = (now - path.stat().st_mtime) / 3600.0
        if age_h < max_age_hours and _CACHE is not None:
            return _CACHE[1], _CACHE[2]

    lines: list[str] | None = None
    source = "disk"
    try:
        if not force_refresh and path.is_file():
            age_h = (now - path.stat().st_mtime) / 3600.0
            if age_h < max_age_hours:
                lines = path.read_text(encoding="utf-8").splitlines()
        if lines is None:
            lines = _fetch_psl_lines()
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            source = "live"
    except (httpx.HTTPError, OSError):
        if path.is_file():
            lines = path.read_text(encoding="utf-8").splitlines()
            source = "disk_stale"
        else:
            raise RuntimeError(
                "Cannot load Public Suffix List (network failed and no cache). "
                f"Expected cache at {path}"
            ) from None

    rules = parse_rule_sections(lines)
    _CACHE = (now, rules, path)
    return rules, path
