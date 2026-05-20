"""Parse DER certificates with cryptography."""

from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from ctscan.models import CertRecord


def _attr_name(attrs, oid) -> str:
    try:
        return attrs.get_attributes_for_oid(oid)[0].value
    except (IndexError, x509.AttributeNotFound):
        return "N/A"


def _format_dt(dt: datetime | None) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def parse_der_certificate(log_index: int, der: bytes) -> CertRecord:
    cert = x509.load_der_x509_certificate(der, default_backend())

    issuer = cert.issuer
    subject = cert.subject
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        # cryptography < 42
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    is_expired = not_after < now

    san: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in ext.value:
            if isinstance(name, x509.DNSName):
                san.append(name.value)
            elif isinstance(name, x509.IPAddress):
                # Many LE precerts only have IP SANs; DNS-only logic yields san=[] and no rule hits
                san.append(str(name.value))
    except x509.ExtensionNotFound:
        pass

    if not san:
        cn = _attr_name(subject, NameOID.COMMON_NAME)
        if cn != "N/A":
            san.append(cn)
    if not san:
        # Allow issuer-only filtering when there is no DNS/IP/CN
        san.append(f"__cert:{log_index}__")

    return CertRecord(
        log_index=log_index,
        issuer_cn=_attr_name(issuer, NameOID.COMMON_NAME),
        issuer_org=_attr_name(issuer, NameOID.ORGANIZATION_NAME),
        issuer_country=_attr_name(issuer, NameOID.COUNTRY_NAME),
        subject_cn=_attr_name(subject, NameOID.COMMON_NAME),
        subject_org=_attr_name(subject, NameOID.ORGANIZATION_NAME),
        subject_country=_attr_name(subject, NameOID.COUNTRY_NAME),
        not_before=_format_dt(not_before),
        not_after=_format_dt(not_after),
        is_expired=is_expired,
        san=san,
        der=der,
    )
