"""DNS lookups via dnspython with LRU caching."""

from __future__ import annotations

from collections import OrderedDict

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype

DNS_CACHE_MAX = 50_000

DNS_RCODE_MAP = {
    "NOERROR": 0,
    "FORMERR": 1,
    "SERVFAIL": 2,
    "NXDOMAIN": 3,
    "NOTIMP": 4,
    "REFUSED": 5,
    "UNKNOWN": -1,
}


def normalize_domain(domain: str) -> str:
    if domain.startswith("*."):
        return domain[2:]
    return domain


class DnsResolver:
    def __init__(self, timeout: float = 3.0, cache_size: int = DNS_CACHE_MAX):
        self.timeout = timeout
        self._cache: OrderedDict[str, dict] = OrderedDict()
        self._cache_size = cache_size

    def _cache_get(self, key: str) -> dict | None:
        if key not in self._cache:
            return None
        self._cache.move_to_end(key)
        return self._cache[key]

    def _cache_set(self, key: str, value: dict) -> None:
        self._cache[key] = value
        self._cache.move_to_end(key)
        while len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)

    def query(self, domain: str, rdtype: str = "A") -> dict:
        domain = normalize_domain(domain)
        cache_key = f"{domain}:{rdtype}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        result = {
            "rcode": "UNKNOWN",
            "flags": [],
            "has_ad": False,
            "has_rrsig": False,
        }
        try:
            q = dns.message.make_query(domain, rdtype)
            response = dns.query.udp(q, "8.8.8.8", timeout=self.timeout)
            result["rcode"] = dns.rcode.to_text(response.rcode()).upper()
            result["flags"] = [dns.flags.to_text(f) for f in response.flags]
            result["has_ad"] = bool(response.flags & dns.flags.AD)
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    result["has_rrsig"] = True
        except dns.exception.DNSException:
            pass

        self._cache_set(cache_key, result)
        return result

    def rcode(self, domain: str) -> int:
        status = self.query(domain)["rcode"]
        return DNS_RCODE_MAP.get(status, -1)

    def status(self, domain: str) -> str:
        return self.query(domain)["rcode"]

    def flags(self, domain: str) -> list[str]:
        return self.query(domain)["flags"]

    def has_flag(self, domain: str, flag: str) -> bool:
        return flag.lower() in [f.lower() for f in self.flags(domain)]

    def is_nxdomain(self, domain: str) -> bool:
        return self.query(domain)["rcode"] == "NXDOMAIN"

    def exists(self, domain: str) -> bool:
        return self.query(domain)["rcode"] == "NOERROR"

    def is_dnssec_secure(self, domain: str) -> bool:
        info = self.query(domain)
        return info["rcode"] == "NOERROR" and (info["has_ad"] or info["has_rrsig"])

    def is_dnssec_insecure(self, domain: str) -> bool:
        info = self.query(domain)
        return info["rcode"] == "NOERROR" and not info["has_ad"] and not info["has_rrsig"]
