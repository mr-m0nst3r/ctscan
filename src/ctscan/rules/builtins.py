"""Built-in functions exposed to the rule engine."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctscan.dns.resolver import DnsResolver


def build_builtins(dns: "DnsResolver") -> dict:
    from ctscan.psl import get_br_icann_checker

    br = get_br_icann_checker()
    def matches(domain: str, pattern: str) -> bool:
        return bool(re.search(pattern, domain))

    def endswith(domain: str, suffix: str) -> bool:
        return domain.endswith(suffix)

    def contains(any_str: str, substring: str) -> bool:
        return substring in any_str

    def is_br_icann_psl_domain(domain: str) -> bool:
        """True if domain's PSL public suffix is in ICANN DOMAINS (not PRIVATE)."""
        r = br.check_name(domain)
        return r.br_icann_ok is True

    def psl_public_suffix(domain: str) -> str:
        """PSL public suffix for domain, or empty string if unknown."""
        r = br.check_name(domain)
        return r.public_suffix or ""

    def psl_section(domain: str) -> str:
        """``icann``, ``private``, or ``unknown`` for domain's public suffix."""
        r = br.check_name(domain)
        return r.psl_section or ""

    return {
        "dns_info": dns.query,
        "dns_rcode": dns.rcode,
        "dns_status": dns.status,
        "dns_flags": dns.flags,
        "dns_has_flag": dns.has_flag,
        "is_nxdomain": dns.is_nxdomain,
        "dns_exists": dns.exists,
        "is_dnssec_secure": dns.is_dnssec_secure,
        "is_dnssec_insecure": dns.is_dnssec_insecure,
        "matches": matches,
        "endswith": endswith,
        "contains": contains,
        "is_br_icann_psl_domain": is_br_icann_psl_domain,
        "psl_public_suffix": psl_public_suffix,
        "psl_section": psl_section,
    }
