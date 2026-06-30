"""Parse embedded SCTs from certificates and match against the CT log list."""

from __future__ import annotations

import base64
from datetime import timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from ctscan.models import CtLogListEntry, ParsedSct, SctLookupResult


def _format_ts(dt) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _hash_algorithm_name(algo) -> str:
    name = getattr(algo, "name", None)
    if name:
        return str(name)
    return algo.__class__.__name__


def _parse_sct(sct, extension: str) -> ParsedSct:
    return ParsedSct(
        log_id_b64=base64.b64encode(sct.log_id).decode(),
        timestamp=_format_ts(sct.timestamp),
        version=str(sct.version),
        hash_algorithm=_hash_algorithm_name(sct.signature_hash_algorithm),
        extension=extension,
    )


def extract_scts_from_certificate(cert: x509.Certificate) -> list[ParsedSct]:
    """Return SCTs embedded in X.509 extensions."""
    found: list[ParsedSct] = []
    for cls, label in (
        (x509.PrecertificateSignedCertificateTimestamps, "precert_scts"),
        (x509.SignedCertificateTimestamps, "embedded_scts"),
    ):
        try:
            ext = cert.extensions.get_extension_for_class(cls)
        except x509.ExtensionNotFound:
            continue
        for sct in ext.value:
            found.append(_parse_sct(sct, label))
    return found


def extract_scts_from_der(der: bytes) -> list[ParsedSct]:
    if der.startswith(b"-----BEGIN"):
        cert = x509.load_pem_x509_certificate(der, default_backend())
    else:
        cert = x509.load_der_x509_certificate(der, default_backend())
    return extract_scts_from_certificate(cert)


def lookup_scts(
    scts: list[ParsedSct],
    log_index: dict[str, CtLogListEntry],
) -> list[SctLookupResult]:
    results: list[SctLookupResult] = []
    for sct in scts:
        entry = log_index.get(sct.log_id_b64)
        if entry is None:
            results.append(SctLookupResult(sct=sct, matched=False))
            continue
        results.append(
            SctLookupResult(
                sct=sct,
                matched=True,
                operator=entry.operator,
                operator_contact=entry.operator_contact,
                description=entry.description,
                url=entry.url or "—",
                state=entry.state,
                state_timestamp=entry.state_timestamp or "—",
                period_start=entry.start,
                period_end=entry.end,
                mmd=str(entry.mmd) if entry.mmd is not None else "—",
                log_kind=entry.log_kind,
                log_type=entry.log_type or "—",
            )
        )
    return results
