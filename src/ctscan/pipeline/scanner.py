"""Scan pipeline orchestration."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import httpx
from rich.console import Console

from ctscan.ct.client import CtClient
from ctscan.ct.http_util import format_connect_error_hint
from ctscan.dns.resolver import DnsResolver, normalize_domain
from ctscan.models import CertRecord
from ctscan.rules.engine import RuleEngine
from ctscan.storage.certs_io import default_certs_dir, save_pem_from_record
from ctscan.psl import get_br_icann_checker
from ctscan.storage.db import Database


@dataclass
class ScanOptions:
    log_uri: str
    target_count: int = 100
    batch_size: int = 50
    delay: float = 0.1
    query: str | None = None
    """Compiled Python rule expression for RuleEngine."""
    job_query: str | None = None
    """Original query text stored in scan_jobs.query (SQL or --filter)."""
    rules_file: str | None = None
    nxdomain_mode: bool = False
    after_date: str | None = None
    save_cert: bool = False
    resume: bool = True
    verbose: bool = False
    trust_env: bool = False
    proxy: str | None = None
    require_br_icann: bool = False
    """Only accept certs whose DNS names use ICANN PSL suffixes (not PRIVATE)."""
    on_match: Callable[[str, str, int, int], None] | None = None


class Scanner:
    def __init__(self, db: Database | None = None, console: Console | None = None):
        self.db = db or Database()
        self.console = console or Console()

    def run(self, opts: ScanOptions) -> int:
        dns = DnsResolver()
        br_checker = get_br_icann_checker() if opts.require_br_icann else None

        engine: RuleEngine | None = None
        if opts.query or opts.rules_file:
            engine = RuleEngine(
                dns,
                rule_str=opts.query,
                rule_file=opts.rules_file,
            )

        certs_dir = default_certs_dir()
        saved_pems = 0
        if opts.save_cert:
            certs_dir.mkdir(parents=True, exist_ok=True)
            self.console.print(
                f"[dim]--save-cert[/] will write PEMs to [cyan]{certs_dir.resolve()}[/]"
            )

        job_id: int
        next_end: int
        known: set[str]
        matched = 0

        with CtClient(
            opts.log_uri,
            trust_env=opts.trust_env,
            proxy=opts.proxy,
        ) as ct:
            try:
                tree_size = ct.get_tree_size()
            except httpx.HTTPError as exc:
                self.console.print(format_connect_error_hint(exc))
                raise SystemExit(1) from exc

            if opts.resume:
                row = self.db.get_active_job()
                if row and row["log_uri"] == opts.log_uri and row["status"] == "running":
                    job_id = int(row["id"])
                    next_end = int(row["next_end_index"])
                    matched = int(row["matched_count"])
                    known = self.db.known_domains(job_id)
                    self.console.print(
                        f"[cyan]Resuming job #{job_id}[/] "
                        f"({matched} hits so far), from index {next_end}"
                    )
                else:
                    job_id, next_end, known, matched = self._new_job(
                        opts, tree_size
                    )
            else:
                job_id, next_end, known, matched = self._new_job(opts, tree_size)

            self.console.print(
                f"CT log size: {tree_size:,}, target hits: {opts.target_count}"
            )
            self.console.print(
                "[dim]Scanning backward from the log tail; the first get-entries "
                "call may take tens of seconds to minutes on large logs.[/]"
            )

            checked = 0
            batches = 0
            last_progress = time.monotonic()

            while matched < opts.target_count and next_end >= 0:
                batch_start = max(0, next_end - opts.batch_size + 1)
                batches += 1

                fetch_msg = (
                    f"[dim]Batch {batches} · get-entries "
                    f"{batch_start:,} … {next_end:,}[/]"
                )
                self.console.print(fetch_msg)

                raw = ct.get_entries(batch_start, next_end)

                if not raw:
                    self.console.print(
                        f"[yellow]Warning:[/] batch returned 0 entries "
                        f"({batch_start:,} … {next_end:,}); "
                        "rate limit or invalid range — continuing."
                    )

                certs: list[CertRecord] = []
                for i, entry in enumerate(raw):
                    rec = ct.parse_entry_at_index(batch_start + i, entry)
                    if rec:
                        certs.append(rec)
                skipped_leaf = len(raw) - len(certs)

                for cert in certs:
                    if opts.after_date and cert.not_before < opts.after_date:
                        continue

                    hit = self._try_match(
                        cert,
                        engine=engine,
                        nxdomain_mode=opts.nxdomain_mode,
                        known=known,
                        dns=dns,
                    )
                    if not hit:
                        continue

                    if br_checker and not br_checker.cert_passes_br_icann(cert):
                        if opts.verbose:
                            bad = [
                                d.name
                                for d in br_checker.check_cert(cert).domains
                                if d.br_icann_ok is False
                            ]
                            self.console.print(
                                f"[dim]  skip log_index {cert.log_index}: "
                                f"BR ICANN PSL failed for {bad}[/]"
                            )
                        continue

                    domain, rule_name = hit
                    if self.db.add_match(
                        job_id,
                        cert.log_index,
                        domain,
                        cert.issuer_cn,
                        cert.issuer_org,
                        cert.not_before,
                        cert.not_after,
                        rule_name,
                    ):
                        matched += 1
                        known.add(normalize_domain(domain))
                        label = f"[{matched}/{opts.target_count}] {domain}"
                        if opts.on_match:
                            opts.on_match(label, rule_name, cert.log_index, matched)
                        else:
                            self.console.print(f"{label} ({rule_name})")

                        if opts.save_cert:
                            if save_pem_from_record(cert, certs_dir):
                                saved_pems += 1
                                self.console.print(
                                    f"[dim]  └ saved {cert.log_index}.pem[/]"
                                )
                            elif cert.der is None:
                                self.console.print(
                                    "[yellow]  └ cannot save PEM: no certificate DER[/]"
                                )

                    if matched >= opts.target_count:
                        break

                checked += len(certs)
                next_end = batch_start - 1
                self.db.update_checkpoint(job_id, next_end, matched)

                now_t = time.monotonic()
                if opts.verbose or batches == 1 or (now_t - last_progress >= 10.0):
                    last_progress = now_t
                    pos_s = ""
                    if tree_size > 0:
                        pos_pct = batch_start / tree_size * 100.0
                        pos_s = f" · ~{pos_pct:.6f}% through log"
                    self.console.print(
                        f"[dim]  └ received {len(raw)} · parsed {len(certs)} certs · "
                        f"unparsed {skipped_leaf} · "
                        f"total parsed {checked} · hits {matched}{pos_s}[/]"
                    )

                if matched >= opts.target_count:
                    break

                time.sleep(opts.delay)

            self.db.complete_job(job_id)

        self.console.print(
            f"[green]Done.[/] {matched} hit(s), database: {self.db.path}"
        )
        if opts.save_cert:
            self.console.print(
                f"[green]PEM directory:[/] {certs_dir.resolve()} "
                f"({saved_pems} new file(s) this run)"
            )
        return matched

    def _new_job(
        self, opts: ScanOptions, tree_size: int
    ) -> tuple[int, int, set[str], int]:
        job_id = self.db.create_job(
            opts.log_uri,
            tree_size,
            opts.target_count,
            opts.job_query if opts.job_query is not None else opts.query,
            opts.nxdomain_mode,
        )
        return job_id, tree_size - 1, set(), 0

    def _try_match(
        self,
        cert: CertRecord,
        *,
        engine: RuleEngine | None,
        nxdomain_mode: bool,
        known: set[str],
        dns: DnsResolver,
    ) -> tuple[str, str] | None:
        names = list(cert.san)
        if not names:
            names = [f"__cert:{cert.log_index}__"]

        for domain in names:
            clean = normalize_domain(domain)
            if clean in known:
                continue

            if nxdomain_mode and not dns.is_nxdomain(clean):
                continue

            eval_domain = clean if nxdomain_mode else domain
            if engine:
                ok, rule_name = engine.match_domain(cert, eval_domain)
                if not ok:
                    continue
            else:
                rule_name = "all"

            return clean if nxdomain_mode else domain, rule_name
        return None
