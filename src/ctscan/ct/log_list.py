"""Google CT log list (online fetch + local cache + built-in fallback)."""

from __future__ import annotations

import json
import time
from collections import defaultdict
from pathlib import Path

import httpx

from ctscan.ct.http_util import build_http_client, request_with_retries
from ctscan.models import CtLogInfo
from ctscan.storage.db import default_data_dir

CT_LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
_CACHE: tuple[float, list[CtLogInfo]] | None = None


def _cache_path() -> Path:
    p = default_data_dir() / "cache" / "all_logs_list.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _builtin_fallback_logs() -> list[CtLogInfo]:
    """Common logs for --pick / logs when gstatic is unreachable (may be outdated)."""
    entries = [
        ("Google 'Argon2026h1' log", "https://ct.googleapis.com/logs/us1/argon2026h1/", "2026", "usable"),
        ("Google 'Argon2025h2' log", "https://ct.googleapis.com/logs/us1/argon2025h2/", "2025", "usable"),
        ("Google 'Argon2025h1' log", "https://ct.googleapis.com/logs/us1/argon2025h1/", "2025", "usable"),
        ("Google 'Argon2024h2' log", "https://ct.googleapis.com/logs/us1/argon2024h2/", "2024", "usable"),
        ("Google 'Argon2024h1' log", "https://ct.googleapis.com/logs/us1/argon2024h1/", "2024", "usable"),
        ("Google 'Xenon2026h1' log", "https://ct.googleapis.com/logs/us1/xenon2026h1/", "2026", "usable"),
        ("Google 'Xenon2025h2' log", "https://ct.googleapis.com/logs/us1/xenon2025h2/", "2025", "usable"),
        ("Cloudflare 'Nimbus2026' Log", "https://ct.cloudflare.com/logs/nimbus2026/", "2026", "usable"),
        ("Cloudflare 'Nimbus2025' Log", "https://ct.cloudflare.com/logs/nimbus2025/", "2025", "usable"),
        ("DigiCert 'Wyvern2026h1' Log", "https://ct1.digicert-ct.com/log/wyvern2026h1/", "2026", "usable"),
        ("DigiCert 'Wyvern2025h2' Log", "https://ct1.digicert-ct.com/log/wyvern2025h2/", "2025", "usable"),
        ("Let's Encrypt 'Oak2026h1'", "https://oak.ct.letsencrypt.org/2026h1/", "2026", "usable"),
        ("Let's Encrypt 'Oak2025h2'", "https://oak.ct.letsencrypt.org/2025h2/", "2025", "usable"),
    ]
    return [
        CtLogInfo(
            description=desc,
            url=url,
            year=year,
            start=f"{year}-01-01",
            end="N/A",
            state=state,
            operator=desc.split()[0].strip("'"),
        )
        for desc, url, year, state in entries
    ]


def _parse_log_list_json(data: dict) -> list[CtLogInfo]:
    logs: list[CtLogInfo] = []
    for operator in data.get("operators", []):
        op_name = operator.get("name", "Unknown")
        for log in operator.get("logs", []):
            temporal = log.get("temporal_interval", {})
            start = temporal.get("start_inclusive", "")
            end = temporal.get("end_exclusive", "")
            year = start[:4] if start else "Unknown"
            state = "unknown"
            if "state" in log:
                state = next(iter(log["state"].keys()))
            logs.append(
                CtLogInfo(
                    description=log.get("description", "N/A"),
                    url=log.get("url", ""),
                    year=year,
                    start=start[:10] if start else "N/A",
                    end=end[:10] if end else "N/A",
                    state=state,
                    operator=op_name,
                )
            )
    return logs


def _load_disk_cache() -> list[CtLogInfo] | None:
    path = _cache_path()
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        logs = _parse_log_list_json(data)
        return logs if logs else None
    except (json.JSONDecodeError, OSError, KeyError):
        return None


def _save_disk_cache(data: dict) -> None:
    try:
        _cache_path().write_text(
            json.dumps(data, ensure_ascii=False, indent=0),
            encoding="utf-8",
        )
    except OSError:
        pass


def _fetch_remote_log_list() -> list[CtLogInfo]:
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            with build_http_client(
                trust_env=False, timeout=httpx.Timeout(60.0)
            ) as client:
                resp = request_with_retries(
                    client, "GET", CT_LOG_LIST_URL, retries=3
                )
                data = resp.json()
            _save_disk_cache(data)
            return _parse_log_list_json(data)
        except Exception as exc:
            last_err = exc
            if attempt < 2:
                time.sleep(1.0 * (attempt + 1))
    raise last_err or RuntimeError("fetch failed")


def fetch_ct_logs(
    force_refresh: bool = False,
    *,
    allow_stale_cache: bool = True,
    allow_builtin_fallback: bool = True,
) -> tuple[list[CtLogInfo], str]:
    """
    Returns (logs, source_hint).

    source_hint: live | memory_cache | disk_cache | builtin | empty
    """
    global _CACHE
    now = time.time()
    if not force_refresh and _CACHE and now - _CACHE[0] < 3600:
        return _CACHE[1], "memory_cache"

    if not force_refresh:
        disk = _load_disk_cache()
        if disk:
            _CACHE = (now, disk)
            return disk, "disk_cache"

    try:
        logs = _fetch_remote_log_list()
        _CACHE = (now, logs)
        return logs, "live"
    except Exception:
        if allow_stale_cache:
            disk = _load_disk_cache()
            if disk:
                _CACHE = (now, disk)
                return disk, "disk_cache_stale"
        if allow_builtin_fallback:
            logs = _builtin_fallback_logs()
            _CACHE = (now, logs)
            return logs, "builtin"
        return [], "empty"


def group_logs_by_year(logs: list[CtLogInfo]) -> dict[str, list[CtLogInfo]]:
    grouped: dict[str, list[CtLogInfo]] = defaultdict(list)
    for log in logs:
        grouped[log.year].append(log)
    return dict(sorted(grouped.items(), reverse=True))


def group_logs_by_operator(logs: list[CtLogInfo]) -> dict[str, list[CtLogInfo]]:
    grouped: dict[str, list[CtLogInfo]] = defaultdict(list)
    for log in logs:
        grouped[log.operator].append(log)
    return dict(sorted(grouped.items()))
