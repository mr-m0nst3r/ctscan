import base64

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from typer.testing import CliRunner

from ctscan.cli import app
from ctscan.ct.roots import (
    cert_sha256_fingerprint,
    decode_roots_response,
    load_cert_der,
    normalize_fingerprint,
    root_matches,
)

runner = CliRunner()


def _make_test_root_der(cn: str = "Test Root CA") -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(__import__("datetime").datetime(2020, 1, 1))
        .not_valid_after(__import__("datetime").datetime(2030, 1, 1))
        .sign(key, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_decode_roots_response():
    der_a = b"\x30\x03\x01\x02\x03"
    der_b = b"\x30\x03\x04\x05\x06"
    data = {
        "certificates": [
            base64.b64encode(der_a).decode(),
            base64.b64encode(der_b).decode(),
        ]
    }
    assert decode_roots_response(data) == [der_a, der_b]


def test_root_matches_exact_der():
    target = _make_test_root_der()
    other = _make_test_root_der("Other Root")
    assert root_matches(target, [other, target])
    assert not root_matches(target, [other])


def test_normalize_fingerprint():
    assert normalize_fingerprint("AA:BB:cc") == "aabbcc"


def test_load_cert_der_pem_and_der(tmp_path):
    der = _make_test_root_der()
    der_path = tmp_path / "root.der"
    der_path.write_bytes(der)
    assert load_cert_der(der_path) == der

    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + base64.encodebytes(der).decode()
        + "-----END CERTIFICATE-----\n"
    )
    pem_path = tmp_path / "root.pem"
    pem_path.write_text(pem, encoding="utf-8")
    assert load_cert_der(pem_path) == der


def test_check_root_requires_one_target():
    result = runner.invoke(app, ["check-root"])
    assert result.exit_code != 0
    assert "exactly one" in result.stdout


def test_check_root_reports_missing(monkeypatch, tmp_path):
    target = _make_test_root_der("Our Root")
    pem_path = tmp_path / "our-root.pem"
    pem_path.write_bytes(
        target
    )  # load_cert_der handles DER in file without PEM headers

    from ctscan.models import CtLogInfo

    logs = [
        CtLogInfo(
            description="Has root log",
            url="https://example.com/log/has/",
            year="2026",
            start="2026-01-01",
            end="2027-01-01",
            state="usable",
            operator="TestOp",
        ),
        CtLogInfo(
            description="Missing root log",
            url="https://example.com/log/missing/",
            year="2026",
            start="2026-01-01",
            end="2027-01-01",
            state="usable",
            operator="TestOp",
        ),
    ]

    def fake_fetch(force_refresh=False, **kwargs):
        return logs, "builtin"

    class FakeCtClient:
        def __init__(self, log_uri, **kwargs):
            self.log_uri = log_uri

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get_roots(self):
            if "has" in self.log_uri:
                return [target, _make_test_root_der("Other")]
            return [_make_test_root_der("Other")]

    monkeypatch.setattr("ctscan.cli.fetch_ct_logs", fake_fetch)
    monkeypatch.setattr("ctscan.cli.CtClient", FakeCtClient)

    result = runner.invoke(
        app,
        ["check-root", "--pem", str(pem_path), "--missing-only"],
    )
    assert result.exit_code == 1
    assert "Missing root log" in result.stdout
    assert "Has root log" not in result.stdout


def test_roots_single_log(monkeypatch):
    der = _make_test_root_der("Listed Root")

    class FakeCtClient:
        def __init__(self, log_uri, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get_roots(self):
            return [der]

    monkeypatch.setattr("ctscan.cli.CtClient", FakeCtClient)

    result = runner.invoke(
        app,
        [
            "roots",
            "--log-uri",
            "https://ct.example.com/log/test/",
        ],
    )
    assert result.exit_code == 0
    assert "Listed Root" in result.stdout
    fp = cert_sha256_fingerprint(der)
    assert fp[:16] in result.stdout
