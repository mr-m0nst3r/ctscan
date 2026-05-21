from pathlib import Path

from ctscan.psl.br_icann import BrIcannChecker
from ctscan.psl.loader import parse_rule_sections
from ctscan.models import CertRecord

FIXTURE = Path(__file__).parent / "fixtures" / "psl_minimal.dat"


def _checker() -> BrIcannChecker:
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    rules = parse_rule_sections(lines)
    return BrIcannChecker(rules, FIXTURE)


def test_parse_rule_sections():
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    rules = parse_rule_sections(lines)
    assert rules["com"] == "icann"
    assert rules["co.uk"] == "icann"
    assert rules["blogspot.com"] == "private"
    assert rules["github.io"] == "private"


def test_icann_domain_passes():
    c = _checker()
    r = c.check_name("www.example.com")
    assert r.br_icann_ok is True
    assert r.psl_section == "icann"
    assert r.public_suffix == "com"


def test_private_blogspot_fails():
    c = _checker()
    r = c.check_name("foo.blogspot.com")
    assert r.br_icann_ok is False
    assert r.psl_section == "private"
    assert r.public_suffix == "blogspot.com"


def test_private_github_io_fails():
    c = _checker()
    r = c.check_name("myapp.github.io")
    assert r.br_icann_ok is False
    assert r.public_suffix == "github.io"


def test_co_uk_icann_passes():
    c = _checker()
    r = c.check_name("www.example.co.uk")
    assert r.br_icann_ok is True
    assert r.public_suffix == "co.uk"


def test_wildcard_san_strips_star():
    c = _checker()
    r = c.check_name("*.example.com")
    assert r.br_icann_ok is True


def test_ip_not_applicable():
    c = _checker()
    r = c.check_name("192.0.2.1")
    assert r.br_icann_ok is None
    assert r.kind == "ip"


def test_cert_all_dns_must_pass():
    c = _checker()
    cert = CertRecord(
        log_index=1,
        san=["www.example.com", "foo.blogspot.com"],
    )
    result = c.check_cert(cert)
    assert result.all_ok is False
    assert result.dns_failed == 1


def test_cert_pass_when_all_icann():
    c = _checker()
    cert = CertRecord(log_index=2, san=["a.example.com", "b.example.org"])
    assert c.cert_passes_br_icann(cert)
