"""Save hit certificates as PEM (~/.ctscan/certs/{log_index}.pem)."""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from ctscan.models import CertRecord
from ctscan.storage.db import default_data_dir


def default_certs_dir() -> Path:
    return default_data_dir() / "certs"


def pem_path_for_index(certs_dir: Path, log_index: int) -> Path:
    return certs_dir / f"{log_index}.pem"


def save_pem_from_der(der: bytes, log_index: int, certs_dir: Path) -> bool:
    """
    Write DER to {log_index}.pem. Skip if file exists (returns False).
    Returns True on successful write.
    """
    if not der:
        return False
    certs_dir.mkdir(parents=True, exist_ok=True)
    path = pem_path_for_index(certs_dir, log_index)
    if path.exists():
        return False
    cert = x509.load_der_x509_certificate(der, default_backend())
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return True


def save_pem_from_record(cert: CertRecord, certs_dir: Path | None = None) -> bool:
    """Save PEM from CertRecord; returns False when der is missing."""
    if cert.der is None:
        return False
    return save_pem_from_der(
        cert.der, cert.log_index, certs_dir or default_certs_dir()
    )
