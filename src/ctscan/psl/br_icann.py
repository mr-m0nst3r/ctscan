"""BR-oriented check: DNS names should use ICANN PSL rules, not PRIVATE DOMAINS suffixes."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import publicsuffix2

from ctscan.dns.resolver import normalize_domain
from ctscan.models import CertRecord
from ctscan.psl.loader import load_psl

_WILDCARD_SAN = re.compile(r"^\*\.", re.IGNORECASE)


@dataclass
class DomainBrCheckResult:
    name: str
    kind: str  # dns_name, ip, invalid
    public_suffix: str | None
    psl_section: str | None  # icann, private, unknown
    br_icann_ok: bool | None  # None when not applicable (IP / invalid)
    reason: str


@dataclass
class CertBrCheckResult:
    log_index: int | None
    all_ok: bool
    dns_checked: int
    dns_failed: int
    domains: list[DomainBrCheckResult] = field(default_factory=list)


class BrIcannChecker:
    """
    CA/Browser Forum style audit helper.

    Flags DNS names whose effective public suffix (PSL match) is listed under
    **PRIVATE DOMAINS** rather than **ICANN DOMAINS** in public_suffix_list.dat.

    Example failures: ``foo.blogspot.com`` (suffix ``blogspot.com`` is private),
    many ``*.amazonaws.com`` patterns, ``foo.github.io``.
    """

    def __init__(
        self,
        rule_sections: dict[str, str],
        psl_path: Path,
    ):
        self.rule_sections = rule_sections
        self._psl = publicsuffix2.PublicSuffixList(psl_file=str(psl_path))

    def check_name(self, name: str) -> DomainBrCheckResult:
        raw = (name or "").strip()
        if not raw or raw.startswith("__cert:"):
            return DomainBrCheckResult(
                name=raw or "(empty)",
                kind="invalid",
                public_suffix=None,
                psl_section=None,
                br_icann_ok=None,
                reason="not a DNS name",
            )

        host = _WILDCARD_SAN.sub("", raw)
        host = normalize_domain(host).lower().rstrip(".")

        if not host or "." not in host:
            return DomainBrCheckResult(
                name=raw,
                kind="invalid",
                public_suffix=None,
                psl_section=None,
                br_icann_ok=None,
                reason="not a FQDN",
            )

        try:
            ipaddress.ip_address(host)
            return DomainBrCheckResult(
                name=raw,
                kind="ip",
                public_suffix=None,
                psl_section=None,
                br_icann_ok=None,
                reason="IP address (BR DNS-name PSL rule does not apply)",
            )
        except ValueError:
            pass

        public_suffix = self._psl.get_tld(host, wildcard=True, strict=False)
        if not public_suffix:
            return DomainBrCheckResult(
                name=raw,
                kind="dns_name",
                public_suffix=None,
                psl_section="unknown",
                br_icann_ok=False,
                reason="no PSL public suffix match",
            )

        section = self.rule_sections.get(public_suffix.lower(), "unknown")
        if section == "icann":
            return DomainBrCheckResult(
                name=raw,
                kind="dns_name",
                public_suffix=public_suffix,
                psl_section=section,
                br_icann_ok=True,
                reason="public suffix is in PSL ICANN DOMAINS",
            )
        if section == "private":
            return DomainBrCheckResult(
                name=raw,
                kind="dns_name",
                public_suffix=public_suffix,
                psl_section=section,
                br_icann_ok=False,
                reason=(
                    "public suffix is in PSL PRIVATE DOMAINS "
                    "(not an ICANN registry suffix; BR audit risk)"
                ),
            )
        return DomainBrCheckResult(
            name=raw,
            kind="dns_name",
            public_suffix=public_suffix,
            psl_section=section,
            br_icann_ok=False,
            reason=f"public suffix section unknown in cached PSL ({section})",
        )

    def check_cert(self, cert: CertRecord) -> CertBrCheckResult:
        names = list(cert.san) if cert.san else []
        if not names and cert.subject_cn and cert.subject_cn != "N/A":
            names = [cert.subject_cn]

        results = [self.check_name(n) for n in names]
        dns_results = [r for r in results if r.kind == "dns_name"]
        failed = [r for r in dns_results if r.br_icann_ok is False]
        if not dns_results:
            all_ok = True
        else:
            all_ok = len(failed) == 0

        return CertBrCheckResult(
            log_index=cert.log_index,
            all_ok=all_ok,
            dns_checked=len(dns_results),
            dns_failed=len(failed),
            domains=results,
        )

    def cert_passes_br_icann(self, cert: CertRecord) -> bool:
        """True if every DNS name in the cert passes the ICANN PSL check."""
        return self.check_cert(cert).all_ok


@lru_cache(maxsize=1)
def get_br_icann_checker() -> BrIcannChecker:
    rules, path = load_psl()
    return BrIcannChecker(rules, path)
