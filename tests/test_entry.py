import pytest

from ctscan.ct.entry import EntryParseError, extract_certificate_der, extract_x509_der


def test_extract_rejects_short_input():
    with pytest.raises(EntryParseError):
        extract_x509_der(b"\x00\x00")


def test_extract_rejects_precert_type_on_x509_only_helper():
    # version=0, leaf_type=0, timestamp=8 zeros, entry_type=1 (precert)
    leaf = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    with pytest.raises(EntryParseError):
        extract_x509_der(leaf)


def test_extract_minimal_x509_entry():
    der = b"\x30\x03\x01\x02\x03"
    cert_len = len(der)
    leaf = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    leaf += bytes([(cert_len >> 16) & 0xFF, (cert_len >> 8) & 0xFF, cert_len & 0xFF])
    leaf += der
    assert extract_x509_der(bytes(leaf)) == der
    assert extract_certificate_der(bytes(leaf), b"") == der


def test_precert_reads_first_cert_from_extra_data():
    der = b"\x30\x03\xAA\xBB\xCC"
    cert_len = len(der)
    extra = bytes(
        [(cert_len >> 16) & 0xFF, (cert_len >> 8) & 0xFF, cert_len & 0xFF]
    ) + der
    leaf = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    leaf += bytes([0, 0, 47])
    leaf += bytes(42)
    assert extract_certificate_der(bytes(leaf), extra) == der
