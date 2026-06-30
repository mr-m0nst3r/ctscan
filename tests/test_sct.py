import base64
import json

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from typer.testing import CliRunner

from ctscan.cli import app
from ctscan.ct.log_list import build_log_id_index, parse_log_entries_from_json
from ctscan.ct.sct import extract_scts_from_der, lookup_scts
from ctscan.models import CtLogListEntry, ParsedSct

runner = CliRunner()


@pytest.fixture
def google_pem(tmp_path):
    path = tmp_path / "google.pem"
    import subprocess

    try:
        proc = subprocess.run(
            [
                "sh",
                "-c",
                "echo | openssl s_client -connect www.google.com:443 "
                "-servername www.google.com 2>/dev/null | openssl x509",
            ],
            capture_output=True,
            timeout=15,
            check=True,
        )
        path.write_bytes(proc.stdout)
        return path
    except (subprocess.SubprocessError, OSError):
        pytest.skip("network/openssl unavailable for live cert fixture")


def test_parse_log_entries_includes_tiled():
    data = {
        "operators": [
            {
                "name": "TestOp",
                "email": ["ops@test.example"],
                "logs": [
                    {
                        "description": "Classic log",
                        "log_id": "Y2xhc3NpYw==",
                        "url": "https://ct.example.com/classic/",
                        "mmd": 86400,
                        "state": {"usable": {"timestamp": "2026-01-01T00:00:00Z"}},
                        "temporal_interval": {
                            "start_inclusive": "2026-01-01T00:00:00Z",
                            "end_exclusive": "2027-01-01T00:00:00Z",
                        },
                    }
                ],
                "tiled_logs": [
                    {
                        "description": "Tiled log",
                        "log_id": "dGlsZWQ=",
                        "submission_url": "https://ct.example.com/tiled/",
                        "mmd": 60,
                        "state": {"pending": {"timestamp": "2026-04-21T00:00:00Z"}},
                        "temporal_interval": {
                            "start_inclusive": "2027-01-01T00:00:00Z",
                            "end_exclusive": "2027-07-01T00:00:00Z",
                        },
                        "log_type": "monitoring_only",
                    }
                ],
            }
        ]
    }
    entries = parse_log_entries_from_json(data)
    assert len(entries) == 2
    by_id = build_log_id_index(entries)
    assert by_id["Y2xhc3NpYw=="].log_kind == "classic"
    assert by_id["dGlsZWQ="].log_kind == "tiled"
    assert by_id["dGlsZWQ="].operator_contact == "ops@test.example"
    assert by_id["dGlsZWQ="].log_type == "monitoring_only"


def test_lookup_scts_known_and_unknown():
    entry = CtLogListEntry(
        operator="Google",
        operator_emails=["a@google.com"],
        description="Argon2026h1",
        log_id="abc123",
        url="https://ct.googleapis.com/logs/argon2026h1/",
        state="usable",
        state_timestamp="2026-01-01 00:00:00",
        start="2026-01-01",
        end="2027-01-01",
        mmd=86400,
        log_kind="classic",
    )
    index = {"abc123": entry}
    scts = [
        ParsedSct(
            log_id_b64="abc123",
            timestamp="2026-06-01 00:00:00 UTC",
            version="Version.v1",
            hash_algorithm="SHA256",
            extension="precert_scts",
        ),
        ParsedSct(
            log_id_b64="missing",
            timestamp="2026-06-01 00:00:00 UTC",
            version="Version.v1",
            hash_algorithm="SHA256",
            extension="precert_scts",
        ),
    ]
    rows = lookup_scts(scts, index)
    assert rows[0].matched and rows[0].operator == "Google"
    assert not rows[1].matched


def test_scts_command_with_mock_index(monkeypatch, tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(__import__("datetime").datetime(2025, 1, 1))
        .not_valid_after(__import__("datetime").datetime(2027, 1, 1))
        .sign(key, hashes.SHA256(), default_backend())
    )
    pem_path = tmp_path / "leaf.pem"
    pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def fake_index(force_refresh=False, **kwargs):
        return {}, "disk_cache"

    monkeypatch.setattr("ctscan.cli.fetch_ct_log_index", fake_index)

    result = runner.invoke(app, ["scts", "--pem", str(pem_path)])
    assert result.exit_code == 1
    assert "No embedded SCTs found" in result.stdout


def test_scts_live_cert(google_pem, monkeypatch):
    from ctscan.storage.db import default_data_dir

    cache = default_data_dir() / "cache" / "all_logs_list.json"
    if not cache.is_file():
        pytest.skip("no log list cache")

    data = json.loads(cache.read_text(encoding="utf-8"))
    index = build_log_id_index(parse_log_entries_from_json(data))

    def fake_index(force_refresh=False, **kwargs):
        return index, "disk_cache"

    monkeypatch.setattr("ctscan.cli.fetch_ct_log_index", fake_index)

    result = runner.invoke(app, ["scts", "--pem", str(google_pem)])
    assert result.exit_code == 0
    assert "Embedded SCTs" in result.stdout
    from ctscan.ct.roots import load_cert_der

    scts = extract_scts_from_der(load_cert_der(google_pem))
    assert scts
    rows = lookup_scts(scts, index)
    assert any(r.matched for r in rows)
