import ast

from ctscan.rules.sql import parse_sql_query


def test_like_and_nxdomain():
    q = parse_sql_query("domain LIKE '%.test' AND is_nxdomain(domain) = true")
    assert "matches(domain" in q
    assert "is_nxdomain(domain) == True" in q or "is_nxdomain(domain) == true".lower() in q.lower()


def test_shell_doubled_apostrophe_is_lets_encrypt():
    """Shell-style 'Let''s Encrypt' must become Let's Encrypt (not Lets Encrypt)."""
    q = parse_sql_query("issuer_org = 'Let''s Encrypt'")
    rhs = q.split("==", 1)[1].strip()
    assert ast.literal_eval(rhs) == "Let's Encrypt"


def test_in_and_or():
    q = parse_sql_query("issuer_country IN ('CN', 'US') OR is_expired = true")
    assert "issuer_country in" in q
    assert " or " in q
    assert "True" in q
