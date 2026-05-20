from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CertRecord:
    """Parsed certificate record (one CT log index)."""

    log_index: int
    issuer_cn: str = "N/A"
    issuer_org: str = "N/A"
    issuer_country: str = "N/A"
    subject_cn: str = "N/A"
    subject_org: str = "N/A"
    subject_country: str = "N/A"
    not_before: str = ""
    not_after: str = ""
    is_expired: bool = False
    san: list[str] = field(default_factory=list)
    der: bytes | None = None

    def as_rule_context(self, domain: str) -> dict:
        return {
            "log_index": self.log_index,
            "issuer_cn": self.issuer_cn,
            "issuer_org": self.issuer_org,
            "issuer_country": self.issuer_country,
            "subject_cn": self.subject_cn,
            "subject_org": self.subject_org,
            "subject_country": self.subject_country,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "is_expired": self.is_expired,
            "san": self.san,
            "domains": self.san,
            "domain": domain,
        }


@dataclass
class CtLogInfo:
    description: str
    url: str
    year: str
    start: str
    end: str
    state: str
    operator: str


@dataclass
class ScanJob:
    id: int
    log_uri: str
    tree_size_at_start: int
    next_end_index: int
    target_count: int
    matched_count: int
    status: str
    query: str | None
    nxdomain_mode: bool
    created_at: datetime
