"""Built-in functions exposed to the rule engine."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctscan.dns.resolver import DnsResolver


def build_builtins(dns: "DnsResolver") -> dict:
    def matches(domain: str, pattern: str) -> bool:
        return bool(re.search(pattern, domain))

    def endswith(domain: str, suffix: str) -> bool:
        return domain.endswith(suffix)

    def contains(any_str: str, substring: str) -> bool:
        return substring in any_str

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
    }
