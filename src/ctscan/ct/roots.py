"""CT log accepted roots (RFC 6962 get-roots)."""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


def decode_roots_response(data: dict) -> list[bytes]:
    """Parse JSON body from ``GET .../ct/v1/get-roots``."""
    roots: list[bytes] = []
    for item in data.get("certificates", []):
        roots.append(base64.b64decode(item))
    return roots


def load_cert_der(path: Path) -> bytes:
    """Load a certificate from PEM or DER."""
    raw = path.read_bytes()
    if b"-----BEGIN" in raw:
        cert = x509.load_pem_x509_certificate(raw, default_backend())
        return cert.public_bytes(encoding=Encoding.DER)
    return raw


def normalize_fingerprint(value: str) -> str:
    """Return lowercase hex SHA-256 without separators."""
    return re.sub(r"[^0-9a-fA-F]", "", value).lower()


def cert_sha256_fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def root_matches(target_der: bytes, roots: list[bytes]) -> bool:
    """True if *target_der* is present in the log's accepted root list."""
    if target_der in roots:
        return True
    target_fp = cert_sha256_fingerprint(target_der)
    return any(cert_sha256_fingerprint(r) == target_fp for r in roots)


def describe_root(der: bytes) -> dict[str, str]:
    """Human-readable fields for a root certificate."""
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
    except ValueError:
        return {
            "subject_cn": "?",
            "subject_org": "?",
            "fingerprint_sha256": cert_sha256_fingerprint(der),
        }

    def _attr(oid) -> str:
        try:
            return cert.subject.get_attributes_for_oid(oid)[0].value
        except (IndexError, x509.AttributeNotFound):
            return "N/A"

    return {
        "subject_cn": _attr(NameOID.COMMON_NAME),
        "subject_org": _attr(NameOID.ORGANIZATION_NAME),
        "fingerprint_sha256": cert_sha256_fingerprint(der),
    }
