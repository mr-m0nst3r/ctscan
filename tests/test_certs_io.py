from datetime import datetime, timezone

from ctscan.storage.certs_io import pem_path_for_index, save_pem_from_der


def test_save_pem_from_der(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    certs_dir = tmp_path / "certs"
    assert save_pem_from_der(der, 42, certs_dir) is True
    p = pem_path_for_index(certs_dir, 42)
    assert p.exists()
    text = p.read_text(encoding="ascii")
    assert "BEGIN CERTIFICATE" in text
    assert save_pem_from_der(der, 42, certs_dir) is False
