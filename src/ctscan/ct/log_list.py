"""Google CT log list (online fetch + local cache + built-in fallback)."""

from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import date
from pathlib import Path

import httpx

from ctscan.ct.http_util import build_http_client, request_with_retries
from ctscan.models import CtLogInfo, CtLogListEntry, CtOperatorInfo
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


def parse_operators_from_json(data: dict) -> list[CtOperatorInfo]:
    """Parse operator names and contact emails from the CT log list JSON."""
    operators: list[CtOperatorInfo] = []
    for op in data.get("operators", []):
        name = op.get("name", "Unknown")
        raw = op.get("email", [])
        if isinstance(raw, str):
            emails = [raw] if raw else []
        elif isinstance(raw, list):
            emails = [str(e) for e in raw if e]
        else:
            emails = []
        operators.append(CtOperatorInfo(name=name, emails=emails))
    return operators


def operator_contact_map(operators: list[CtOperatorInfo]) -> dict[str, str]:
    return {op.name: op.contact for op in operators}


def _operator_emails(operator: dict) -> list[str]:
    raw = operator.get("email", [])
    if isinstance(raw, str):
        return [raw] if raw else []
    if isinstance(raw, list):
        return [str(e) for e in raw if e]
    return []


def _parse_one_log_entry(
    operator: dict,
    log: dict,
    *,
    log_kind: str,
) -> CtLogListEntry | None:
    log_id = log.get("log_id")
    if not log_id:
        return None
    temporal = log.get("temporal_interval", {})
    start = temporal.get("start_inclusive", "")
    end = temporal.get("end_exclusive", "")
    state = "unknown"
    state_timestamp = ""
    state_obj = log.get("state", {})
    if state_obj:
        state = next(iter(state_obj.keys()))
        details = state_obj.get(state) or {}
        state_timestamp = str(details.get("timestamp", ""))[:19].replace("T", " ")
    url = (
        log.get("url")
        or log.get("submission_url")
        or log.get("monitoring_url")
        or ""
    )
    mmd = log.get("mmd")
    return CtLogListEntry(
        operator=operator.get("name", "Unknown"),
        operator_emails=_operator_emails(operator),
        description=log.get("description", "N/A"),
        log_id=log_id,
        url=url.rstrip("/") + ("/" if url and not url.endswith("/") else ""),
        state=state,
        state_timestamp=state_timestamp,
        start=start[:10] if start else "N/A",
        end=end[:10] if end else "N/A",
        mmd=int(mmd) if mmd is not None else None,
        log_kind=log_kind,
        log_type=log.get("log_type"),
    )


def parse_log_entries_from_json(data: dict) -> list[CtLogListEntry]:
    """Parse classic and tiled logs with ``log_id`` for SCT lookup."""
    entries: list[CtLogListEntry] = []
    for operator in data.get("operators", []):
        for log in operator.get("logs", []):
            entry = _parse_one_log_entry(operator, log, log_kind="classic")
            if entry:
                entries.append(entry)
        for log in operator.get("tiled_logs", []):
            entry = _parse_one_log_entry(operator, log, log_kind="tiled")
            if entry:
                entries.append(entry)
    return entries


def build_log_id_index(entries: list[CtLogListEntry]) -> dict[str, CtLogListEntry]:
    return {entry.log_id: entry for entry in entries}


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


def _load_disk_cache_data() -> dict | None:
    path = _cache_path()
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _load_disk_cache() -> list[CtLogInfo] | None:
    data = _load_disk_cache_data()
    if not data:
        return None
    try:
        logs = _parse_log_list_json(data)
        return logs if logs else None
    except KeyError:
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


def fetch_log_list_data(
    force_refresh: bool = False,
    *,
    allow_stale_cache: bool = True,
    allow_builtin_fallback: bool = True,
) -> tuple[dict | None, str]:
    """
    Return raw ``all_logs_list.json`` and source hint.

    ``data`` is None when only the built-in fallback is available (no operator emails).
    """
    global _CACHE
    now = time.time()
    if not force_refresh and _CACHE and now - _CACHE[0] < 3600:
        disk = _load_disk_cache_data()
        if disk:
            return disk, "memory_cache"

    if not force_refresh:
        disk = _load_disk_cache_data()
        if disk:
            return disk, "disk_cache"

    try:
        logs = _fetch_remote_log_list()
        _CACHE = (now, logs)
        disk = _load_disk_cache_data()
        return disk, "live"
    except Exception:
        if allow_stale_cache:
            disk = _load_disk_cache_data()
            if disk:
                _CACHE = (now, _parse_log_list_json(disk))
                return disk, "disk_cache_stale"
        if allow_builtin_fallback:
            _CACHE = (now, _builtin_fallback_logs())
            return None, "builtin"
        return None, "empty"


def fetch_ct_operators(
    force_refresh: bool = False,
    *,
    allow_stale_cache: bool = True,
    allow_builtin_fallback: bool = True,
) -> tuple[list[CtOperatorInfo], str]:
    data, source = fetch_log_list_data(
        force_refresh,
        allow_stale_cache=allow_stale_cache,
        allow_builtin_fallback=allow_builtin_fallback,
    )
    if data:
        return parse_operators_from_json(data), source
    if source == "builtin":
        names = sorted({log.operator for log in _builtin_fallback_logs()})
        return [CtOperatorInfo(name=n) for n in names], source
    return [], source


def fetch_ct_log_index(
    force_refresh: bool = False,
    *,
    allow_stale_cache: bool = True,
    allow_builtin_fallback: bool = True,
) -> tuple[dict[str, CtLogListEntry], str]:
    """Return ``log_id`` → log metadata index from the cached log list."""
    data, source = fetch_log_list_data(
        force_refresh,
        allow_stale_cache=allow_stale_cache,
        allow_builtin_fallback=allow_builtin_fallback,
    )
    if data:
        return build_log_id_index(parse_log_entries_from_json(data)), source
    return {}, source


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


def parse_iso_date(value: str) -> date | None:
    """Parse ``YYYY-MM-DD`` (or longer ISO prefix). Returns None for empty/N/A."""
    if not value or value == "N/A":
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def log_overlaps_interval(log: CtLogInfo, start: date, end: date) -> bool:
    """
    True if log ``temporal_interval`` overlaps ``[start, end]`` (inclusive days).

    Log list ``end`` is ``end_exclusive`` (last active day is the day before).
    """
    log_start = parse_iso_date(log.start)
    if log_start is None:
        return False
    log_end = parse_iso_date(log.end)
    if log_start > end:
        return False
    if log_end is not None and log_end <= start:
        return False
    return True


def select_logs_for_interval(
    logs: list[CtLogInfo],
    start: date,
    end: date,
    *,
    usable_only: bool = True,
) -> list[CtLogInfo]:
    """
    Logs whose temporal interval overlaps ``[start, end]``, newest first.

    Skips entries without a URL. When ``usable_only``, keeps ``state == usable``.
    """
    if start > end:
        raise ValueError("start date must be on or before end date")

    selected: list[CtLogInfo] = []
    for log in logs:
        if usable_only and log.state != "usable":
            continue
        if not log.url.strip():
            continue
        if log_overlaps_interval(log, start, end):
            selected.append(log)

    selected.sort(
        key=lambda log: (parse_iso_date(log.start) or date.min, log.description),
        reverse=True,
    )
    return selected
