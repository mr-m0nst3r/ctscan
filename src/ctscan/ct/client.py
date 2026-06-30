"""CT log HTTP client (RFC 6962)."""

from __future__ import annotations

import base64
from typing import Any, Iterator

import httpx

from ctscan.ct.entry import EntryParseError, extract_certificate_der
from ctscan.ct.http_util import build_http_client, request_with_retries
from ctscan.ct.roots import decode_roots_response
from ctscan.ct.x509_parse import parse_der_certificate
from ctscan.models import CertRecord


class CtClient:
    def __init__(
        self,
        log_uri: str,
        timeout: httpx.Timeout | float | None = None,
        *,
        trust_env: bool = False,
        proxy: str | None = None,
        retries: int = 3,
    ):
        self.log_uri = log_uri.rstrip("/") + "/"
        self._retries = max(1, retries)
        t = timeout
        if isinstance(t, (int, float)):
            t = httpx.Timeout(t)
        self._client = build_http_client(
            trust_env=trust_env,
            proxy=proxy,
            timeout=t if isinstance(t, httpx.Timeout) else None,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "CtClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def _get(self, url: str, **params: Any) -> httpx.Response:
        return request_with_retries(
            self._client,
            "GET",
            url,
            retries=self._retries,
            params=params or None,
        )

    def get_tree_size(self) -> int:
        url = f"{self.log_uri}ct/v1/get-sth"
        resp = self._get(url)
        return int(resp.json()["tree_size"])

    def get_roots(self) -> list[bytes]:
        """Return accepted root certificates (DER) from ``ct/v1/get-roots``."""
        url = f"{self.log_uri}ct/v1/get-roots"
        resp = self._get(url)
        return decode_roots_response(resp.json())

    def get_entries(self, start: int, end: int) -> list[dict]:
        """Fetch entries in the closed interval [start, end] (RFC 6962)."""
        if start < 0 or end < start:
            raise ValueError(f"invalid range: {start}..{end}")
        url = f"{self.log_uri}ct/v1/get-entries"
        resp = self._get(url, start=start, end=end)
        return resp.json().get("entries", [])

    def parse_entry_at_index(self, index: int, raw_entry: dict) -> CertRecord | None:
        try:
            leaf = base64.b64decode(raw_entry["leaf_input"])
            extra = base64.b64decode(raw_entry.get("extra_data") or "")
            der = extract_certificate_der(leaf, extra)
            return parse_der_certificate(index, der)
        except (EntryParseError, KeyError, ValueError):
            return None

    def iter_certs_backward(
        self,
        batch_size: int,
        start_end_index: int | None = None,
    ) -> Iterator[tuple[int, int, list[CertRecord]]]:
        """
        Iterate backward from the log tail in batches.

        Yields:
            (batch_start, batch_end, certs) — indices are inclusive.
        """
        tree_size = self.get_tree_size()
        if tree_size == 0:
            return

        end = start_end_index if start_end_index is not None else tree_size - 1

        while end >= 0:
            start = max(0, end - batch_size + 1)
            raw_entries = self.get_entries(start, end)
            certs: list[CertRecord] = []
            for i, raw in enumerate(raw_entries):
                idx = start + i
                rec = self.parse_entry_at_index(idx, raw)
                if rec:
                    certs.append(rec)
            yield start, end, certs
            end = start - 1
