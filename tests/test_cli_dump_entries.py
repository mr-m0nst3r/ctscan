from typer.testing import CliRunner

import base64
import json

import ctscan.cli as cli


runner = CliRunner()


class _FakeCtClient:
    def __init__(self, log_uri: str, **kwargs):
        self.log_uri = log_uri

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def get_tree_size(self) -> int:
        return 10

    def get_entries(self, start: int, end: int):
        # return (end-start+1) dummy entries, preserving base64-like fields
        return [
            {"leaf_input": f"leaf{idx}", "extra_data": f"extra{idx}"}
            for idx in range(start, end + 1)
        ]


def test_dump_entries_writes_jsonl(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "CtClient", _FakeCtClient)
    out = tmp_path / "out.jsonl"
    result = runner.invoke(
        cli.app,
        [
            "dump-entries",
            "--log-uri",
            "https://example.com/log/",
            "--start",
            "2",
            "--end",
            "5",
            "--batch-size",
            "2",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0
    text = out.read_text(encoding="utf-8").splitlines()
    # 1 metadata line + 4 entries
    assert len(text) == 5
    assert '"type": "ctscan_dump_entries"' in text[0]
    assert '"index": 2' in text[1]
    assert '"index": 5' in text[-1]


def test_parse_dump_lists_timestamp_and_der_b64(tmp_path):
    # Build a minimal dump JSONL with one entry.
    dump = tmp_path / "dump.jsonl"

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timezone

    # leaf_input needs at least 10 bytes, with timestamp at 2..10.
    ts_ms = 1720000000000
    leaf = bytes([0, 0]) + ts_ms.to_bytes(8, "big") + b"\x00" * 10
    # Make it a precert entry_type=1 so extract_certificate_der reads from extra_data.
    # entry_type lives at offsets 10..12 of leaf_input.
    leaf = leaf[:10] + bytes([0, 1]) + leaf[12:]

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com"), x509.DNSName("www.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(encoding=Encoding.DER)
    extra = len(cert_der).to_bytes(3, "big") + cert_der

    dump.write_text(
        "\n".join(
            [
                json.dumps({"type": "ctscan_dump_entries", "log_uri": "x", "tree_size": 1, "start": 0, "end": 0, "batch_size": 1}),
                json.dumps(
                    {
                        "index": 7,
                        "entry": {
                            "leaf_input": base64.b64encode(leaf).decode("ascii"),
                            "extra_data": base64.b64encode(extra).decode("ascii"),
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    out = tmp_path / "parsed.jsonl"
    result = runner.invoke(
        cli.app,
        ["parse-dump", "--input", str(dump), "--output", str(out), "--limit", "1"],
    )
    assert result.exit_code == 0
    rows = out.read_text(encoding="utf-8").splitlines()
    assert len(rows) == 1
    obj = json.loads(rows[0])
    assert obj["index"] == 7
    assert obj["timestamp_ms"] == ts_ms
    assert obj["cert_der_b64"] == base64.b64encode(cert_der).decode("ascii")
    assert "issuer_cn" in obj
    assert "subject_cn" in obj
    assert "not_before" in obj
    assert "domain" in obj
    assert "san" in obj


def test_parse_dump_writes_csv(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timezone

    dump = tmp_path / "dump.jsonl"
    ts_ms = 1720000000000
    leaf = bytes([0, 0]) + ts_ms.to_bytes(8, "big") + b"\x00" * 10
    leaf = leaf[:10] + bytes([0, 1]) + leaf[12:]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(encoding=Encoding.DER)
    extra = len(cert_der).to_bytes(3, "big") + cert_der
    dump.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "type": "ctscan_dump_entries",
                        "log_uri": "x",
                        "tree_size": 1,
                        "start": 0,
                        "end": 0,
                        "batch_size": 1,
                    }
                ),
                json.dumps(
                    {
                        "index": 7,
                        "entry": {
                            "leaf_input": base64.b64encode(leaf).decode("ascii"),
                            "extra_data": base64.b64encode(extra).decode("ascii"),
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    out = tmp_path / "parsed.csv"
    result = runner.invoke(
        cli.app,
        ["parse-dump", "--input", str(dump), "--csv", str(out), "--limit", "1"],
    )
    assert result.exit_code == 0
    text = out.read_text(encoding="utf-8").splitlines()
    assert (
        text[0]
        == "index,timestamp_ms,timestamp_utc,issuer_cn,issuer_org,subject_cn,subject_org,not_before,not_after,domain,san,cert_der_b64"
    )
    assert text[1].startswith(f"7,{ts_ms},")
    assert text[1].endswith(base64.b64encode(cert_der).decode("ascii"))

