"""RFC 6962 MerkleTreeLeaf / get-entries parsing.

Most CT log entries are precerts (LogEntryType=1); the certificate DER lives in
``extra_data`` at the head of the ASN.1Cert chain. Entries with a full X.509 only in
``leaf_input`` (type=0) are rare — parsing only those skips most entries and breaks filters.
"""

from __future__ import annotations


class EntryParseError(ValueError):
    pass


def _read_tls_style_asn1_cert(data: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Read TLS/CT style: 24-bit BE length + DER certificate."""
    if len(data) < offset + 3:
        raise EntryParseError("buffer too short for certificate length prefix")
    cert_len = (
        (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]
    ) & 0xFFFFFF
    body_start = offset + 3
    body_end = body_start + cert_len
    if body_end > len(data):
        raise EntryParseError("certificate length exceeds buffer")
    return data[body_start:body_end], body_end


def extract_x509_der(leaf_input: bytes) -> bytes:
    """
    Extract certificate DER from leaf_input for **X509LogEntry only** (entry_type == 0).

    For precert entries use extract_certificate_der.
    """
    if len(leaf_input) < 15:
        raise EntryParseError("leaf_input too short")

    version = leaf_input[0]
    leaf_type = leaf_input[1]
    if version != 0 or leaf_type != 0:
        raise EntryParseError(f"unsupported leaf header: v={version} type={leaf_type}")

    entry_type = (leaf_input[10] << 8) | leaf_input[11]
    if entry_type != 0:
        raise EntryParseError(f"not x509 entry (type={entry_type})")

    offset = 12
    cert_len = (
        (leaf_input[offset] << 16)
        | (leaf_input[offset + 1] << 8)
        | leaf_input[offset + 2]
    )
    offset += 3
    end = offset + cert_len
    if end > len(leaf_input):
        raise EntryParseError("certificate length exceeds leaf_input")

    return leaf_input[offset:end]


def extract_certificate_der(leaf_input: bytes, extra_data: bytes = b"") -> bytes:
    """Return leaf certificate DER from a CT entry (X509 or precert + extra_data)."""
    if len(leaf_input) < 12:
        raise EntryParseError("leaf_input too short")

    version = leaf_input[0]
    leaf_type = leaf_input[1]
    if version != 0 or leaf_type != 0:
        raise EntryParseError(f"unsupported leaf header: v={version} type={leaf_type}")

    entry_type = (leaf_input[10] << 8) | leaf_input[11]

    if entry_type == 0:
        return extract_x509_der(leaf_input)

    if entry_type == 1:
        # PrecertChainEntry: first cert is the precertificate (RFC 6962)
        if not extra_data:
            raise EntryParseError("precert entry requires extra_data")
        cert_der, _ = _read_tls_style_asn1_cert(extra_data, 0)
        return cert_der

    raise EntryParseError(f"unknown LogEntryType: {entry_type}")
