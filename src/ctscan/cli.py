"""Typer CLI entrypoint."""

from __future__ import annotations

import json
import base64
import csv
from datetime import date
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from ctscan.ct.client import CtClient
from ctscan.ct.http_util import default_roots_timeout
from ctscan.ct.log_list import (
    fetch_ct_logs,
    fetch_ct_log_index,
    fetch_ct_operators,
    group_logs_by_operator,
    group_logs_by_year,
    operator_contact_map,
    parse_iso_date,
    select_logs_for_interval,
)
from ctscan.ct.roots import (
    cert_sha256_fingerprint,
    describe_root,
    load_cert_der,
    normalize_fingerprint,
    root_matches,
)
from ctscan.ct.sct import extract_scts_from_der, lookup_scts
from ctscan.ct.x509_parse import parse_der_certificate
from ctscan.pipeline.interval_scan import (
    IntervalScanCoordinator,
    ScanLogTarget,
    group_targets_by_operator,
)
from ctscan.pipeline.scanner import ScanOptions, Scanner
from ctscan.psl import CertBrCheckResult, get_br_icann_checker
from ctscan.psl.loader import load_psl
from ctscan.rules.sql import parse_sql_query
from ctscan.storage.certs_io import (
    default_certs_dir,
    pem_path_for_index,
    save_pem_from_record,
)
from ctscan.storage.db import Database, default_data_dir

app = typer.Typer(
    name="ctscan",
    help="Personal CT certificate scanning CLI",
    no_args_is_help=True,
)
console = Console()


def _iter_entry_ranges(start: int, end: int, batch_size: int) -> list[tuple[int, int]]:
    if batch_size <= 0:
        raise ValueError("batch_size must be > 0")
    if start < 0 or end < start:
        raise ValueError("invalid range")
    ranges: list[tuple[int, int]] = []
    cur = start
    while cur <= end:
        r_end = min(end, cur + batch_size - 1)
        ranges.append((cur, r_end))
        cur = r_end + 1
    return ranges


def _parse_ct_leaf_timestamp_ms(leaf_input: bytes) -> int:
    """
    RFC 6962 MerkleTreeLeaf: timestamp is 8 bytes at offset 2..10 (ms since epoch).
    """
    if len(leaf_input) < 10:
        raise ValueError("leaf_input too short for timestamp")
    return int.from_bytes(leaf_input[2:10], "big")


def _print_cert_br_check(result: CertBrCheckResult) -> None:
    title = "BR ICANN PSL check"
    if result.log_index is not None:
        title += f" (log_index {result.log_index})"
    if result.all_ok:
        console.print(f"[green]{title}: PASS[/] ({result.dns_checked} DNS name(s))")
    else:
        console.print(
            f"[red]{title}: FAIL[/] "
            f"({result.dns_failed}/{result.dns_checked} DNS name(s) non-compliant)"
        )
    table = Table()
    table.add_column("Name")
    table.add_column("Kind")
    table.add_column("Public suffix")
    table.add_column("PSL section")
    table.add_column("OK")
    table.add_column("Reason")
    for d in result.domains:
        ok_s = "—"
        if d.br_icann_ok is True:
            ok_s = "yes"
        elif d.br_icann_ok is False:
            ok_s = "no"
        style = "red" if d.br_icann_ok is False else None
        table.add_row(
            d.name,
            d.kind,
            d.public_suffix or "—",
            d.psl_section or "—",
            ok_s,
            d.reason,
            style=style,
        )
    console.print(table)


def _parse_scan_date(label: str, value: str) -> date:
    parsed = parse_iso_date(value.strip())
    if parsed is None:
        console.print(f"[red]Invalid {label} date:[/] {value!r} (use YYYY-MM-DD)")
        raise typer.Exit(1)
    return parsed


def _resolve_scan_log_uris(
    *,
    log_uri: str | None,
    pick: bool,
    from_date: str | None,
    to_date: str | None,
    usable_only: bool,
    refresh: bool,
) -> list[ScanLogTarget]:
    """
    Return CT logs to scan for this invocation.
    """
    if log_uri:
        if from_date or to_date:
            console.print("[red]Use either --log-uri or --from/--to, not both[/]")
            raise typer.Exit(1)
        if pick:
            console.print("[red]Use either --log-uri or --pick, not both[/]")
            raise typer.Exit(1)
        uri = log_uri.rstrip("/") + "/"
        return [ScanLogTarget(uri=uri, label="single log", operator="manual")]

    if pick:
        if from_date or to_date:
            console.print("[red]Use either --pick or --from/--to, not both[/]")
            raise typer.Exit(1)
        uri = _interactive_pick_log()
        operator = "manual"
        logs, _ = fetch_ct_logs()
        for log in logs:
            if log.url.rstrip("/") + "/" == uri:
                operator = log.operator
                break
        return [ScanLogTarget(uri=uri, label="picked log", operator=operator)]

    if not from_date and not to_date:
        console.print(
            "[red]Specify --log-uri, --pick, or a time interval (--from / --to)[/]"
        )
        raise typer.Exit(1)

    start = _parse_scan_date("--from", from_date) if from_date else date(2013, 1, 1)
    end = _parse_scan_date("--to", to_date) if to_date else date.today()
    if start > end:
        console.print("[red]--from must be on or before --to[/]")
        raise typer.Exit(1)

    logs, source = fetch_ct_logs(force_refresh=refresh)
    if source in ("disk_cache", "memory_cache"):
        console.print("[dim]Using cached log list for interval match[/]")
    elif source == "disk_cache_stale":
        console.print(
            "[yellow]Cannot reach gstatic; using stale local cache for interval match.[/]"
        )
    elif source == "builtin":
        console.print(
            "[yellow]Cannot reach gstatic; interval match uses built-in common logs.[/]"
        )
    elif source == "empty":
        console.print("[red]No log list available to resolve --from/--to.[/]")
        raise typer.Exit(1)

    try:
        matched = select_logs_for_interval(
            logs, start, end, usable_only=usable_only
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from exc

    if not matched:
        scope = "usable " if usable_only else ""
        console.print(
            f"[red]No {scope}logs overlap {start} … {end}.[/] "
            "Try --include-all-states or widen the interval."
        )
        raise typer.Exit(1)

    console.print(
        f"Interval [cyan]{start}[/] … [cyan]{end}[/] → "
        f"[bold]{len(matched)}[/] log(s):"
    )
    for log in matched:
        console.print(
            f"  [{log.state}] {log.description} ({log.start} ~ {log.end})",
            markup=False,
        )
    console.print()

    return [
        ScanLogTarget(
            uri=log.url.rstrip("/") + "/",
            label=log.description,
            operator=log.operator,
        )
        for log in matched
        if log.url
    ]


def _prompt_log_uri_manual() -> str:
    console.print(
        "[yellow]Could not fetch the online log list (network/SSL).[/] "
        "Enter a CT log URL directly."
    )
    default = "https://ct.googleapis.com/logs/us1/argon2026h1/"
    uri = typer.prompt("CT Log URL", default=default).strip()
    if not uri:
        console.print("[red]No URL entered[/]")
        raise typer.Exit(1)
    return uri.rstrip("/") + "/"


def _interactive_pick_log() -> str:
    logs, source = fetch_ct_logs()
    if source == "live":
        pass
    elif source in ("disk_cache", "memory_cache"):
        console.print("[dim]Using cached log list (memory/disk)[/]")
    elif source == "disk_cache_stale":
        console.print(
            "[yellow]Cannot reach gstatic; using stale local cache.[/] "
            f"Cache: {default_data_dir() / 'cache' / 'all_logs_list.json'}"
        )
    elif source == "builtin":
        console.print(
            "[yellow]Cannot reach gstatic; using built-in common logs (may be outdated).[/] "
            "You can also pass [cyan]--log-uri URL[/] to skip selection."
        )
    else:
        return _prompt_log_uri_manual()

    if not logs:
        return _prompt_log_uri_manual()

    by_year = group_logs_by_year(logs)
    years = list(by_year.keys())
    console.print("\n[bold]Pick year[/]")
    for i, year in enumerate(years, 1):
        usable = sum(1 for l in by_year[year] if l.state == "usable")
        console.print(f"  {i:2d}. {year} ({usable}/{len(by_year[year])} usable)")

    choice = typer.prompt("Year number", default="1")
    try:
        year = years[int(choice) - 1]
    except (ValueError, IndexError):
        console.print("[red]Invalid number[/]")
        raise typer.Exit(1)
    year_logs = by_year[year]

    by_op = group_logs_by_operator(year_logs)
    operators = list(by_op.keys())
    console.print(f"\n[bold]{year} — pick operator[/]")
    for i, op in enumerate(operators, 1):
        usable = sum(1 for l in by_op[op] if l.state == "usable")
        console.print(f"  {i:2d}. {op} ({usable}/{len(by_op[op])})")

    choice = typer.prompt("Operator number", default="1")
    try:
        op_logs = by_op[operators[int(choice) - 1]]
    except (ValueError, IndexError):
        console.print("[red]Invalid number[/]")
        raise typer.Exit(1)

    console.print("\n[bold]Pick CT log[/]")
    for i, log in enumerate(op_logs, 1):
        console.print(f"  {i:2d}. [{log.state}] {log.description}", markup=False)

    choice = typer.prompt("Log number", default="1")
    try:
        selected = op_logs[int(choice) - 1]
    except (ValueError, IndexError):
        console.print("[red]Invalid number[/]")
        raise typer.Exit(1)
    uri = selected.url.rstrip("/") + "/"
    console.print(f"\nSelected: [cyan]{selected.description}[/]\n{uri}\n")
    return uri


@app.command("logs")
def cmd_logs(
    refresh: bool = typer.Option(
        False, "--refresh", help="Force refresh of the online log list cache"
    ),
    contacts: bool = typer.Option(
        False,
        "--contacts",
        help="Show CT operator contact emails from the log list",
    ),
):
    """List all CT log servers."""
    logs, source = fetch_ct_logs(force_refresh=refresh)
    if source != "live":
        console.print(f"[dim]List source: {source}[/]\n")
    if not logs:
        console.print("[red]No log list available (network failed and no cache).[/]")
        raise typer.Exit(1)

    contacts_map: dict[str, str] = {}
    if contacts:
        operators, op_source = fetch_ct_operators(force_refresh=refresh)
        contacts_map = operator_contact_map(operators)
        if op_source in ("builtin", "empty"):
            console.print(
                "[yellow]Operator emails unavailable without log list cache.[/] "
                "Try [cyan]ctscan logs --refresh --contacts[/]\n"
            )

    by_year = group_logs_by_year(logs)
    for year, year_logs in by_year.items():
        console.print(f"\n[bold]=== {year} ===[/]")
        for log in year_logs:
            console.print(f"  [{log.state}] {log.description}", markup=False)
            console.print(f"      {log.url}")
            line = f"      {log.start} ~ {log.end} | {log.operator}"
            if contacts:
                line += f" | {contacts_map.get(log.operator, '—')}"
            console.print(line)


@app.command("operators")
def cmd_operators(
    refresh: bool = typer.Option(
        False, "--refresh", help="Force refresh of the online log list cache"
    ),
):
    """List CT log operators and contact emails from ``all_logs_list.json``."""
    operators, source = fetch_ct_operators(force_refresh=refresh)
    if source != "live":
        console.print(f"[dim]List source: {source}[/]\n")
    if not operators:
        console.print("[red]No operator list available.[/]")
        raise typer.Exit(1)
    if source in ("builtin", "empty"):
        console.print(
            "[yellow]Built-in fallback has no operator emails.[/] "
            "Run [cyan]ctscan operators --refresh[/] when online.\n"
        )

    table = Table(title="CT log operators")
    table.add_column("Operator")
    table.add_column("Email")
    table.add_column("Logs", justify="right")
    logs, _ = fetch_ct_logs(force_refresh=False)
    counts: dict[str, int] = {}
    for log in logs:
        counts[log.operator] = counts.get(log.operator, 0) + 1
    for op in sorted(operators, key=lambda o: o.name.lower()):
        table.add_row(op.name, op.contact, str(counts.get(op.name, 0)))
    console.print(table)


@app.command("scan")
def cmd_scan(
    log_uri: Optional[str] = typer.Option(None, "--log-uri", help="CT log URL"),
    pick: bool = typer.Option(
        False, "--pick", help="Interactively pick a CT log"
    ),
    query: Optional[str] = typer.Option(
        None, "--query", "-q", help="SQL-style filter condition"
    ),
    filter_expr: Optional[str] = typer.Option(
        None,
        "--filter",
        "-f",
        help="Python filter expression (advanced; mutually exclusive with --query)",
    ),
    rules: Optional[Path] = typer.Option(
        None, "--rules", "-r", help="JSON rules file"
    ),
    nxdomain: bool = typer.Option(
        False, "--nxdomain", help="Keep only NXDOMAIN domains"
    ),
    target: int = typer.Option(100, "--target", "-n", help="Target number of hits"),
    batch_size: int = typer.Option(50, "--batch-size", help="Entries per batch"),
    delay: float = typer.Option(0.1, "--delay", help="Delay between batches (seconds)"),
    after_date: Optional[str] = typer.Option(
        None,
        "--after-date",
        help="Only certs with not_before >= this date (string compare)",
    ),
    save_cert: bool = typer.Option(
        False, "--save-cert", help="Save PEM files to ~/.ctscan/certs"
    ),
    no_resume: bool = typer.Option(
        False, "--no-resume", help="Do not resume; always start a new job"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Print per-batch HTTP index details"
    ),
    use_env_proxy: bool = typer.Option(
        False,
        "--use-env-proxy",
        help="Use HTTP_PROXY/HTTPS_PROXY from environment (default: direct)",
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", help="Explicit proxy URL (overrides environment)"
    ),
    require_br_icann: bool = typer.Option(
        False,
        "--require-br-icann",
        help="Only keep certs whose DNS names use PSL ICANN DOMAINS (not PRIVATE)",
    ),
    db_path: Optional[Path] = typer.Option(
        None, "--db", help="SQLite path (default ~/.ctscan/ctscan.db)"
    ),
    from_date: Optional[str] = typer.Option(
        None,
        "--from",
        help="Interval start (YYYY-MM-DD); auto-select CT logs overlapping this range",
    ),
    to_date: Optional[str] = typer.Option(
        None,
        "--to",
        help="Interval end (YYYY-MM-DD, inclusive); default today when --from is set",
    ),
    refresh: bool = typer.Option(
        False,
        "--refresh",
        help="Refresh log list before resolving --from/--to",
    ),
    usable_only: bool = typer.Option(
        True,
        "--usable-only/--include-all-states",
        help="When using --from/--to, only scan logs in usable state",
    ),
    concurrency: Optional[int] = typer.Option(
        None,
        "--concurrency",
        "-j",
        help="Max parallel CT operators for interval scan (default: all operators)",
    ),
):
    """Scan CT log(s) and write matches to SQLite."""
    if query and filter_expr:
        console.print("[red]Cannot use both --query and --filter[/]")
        raise typer.Exit(1)

    interval_from: str | None = None
    interval_to: str | None = None
    if from_date or to_date:
        interval_from = from_date or "2013-01-01"
        interval_to = to_date or date.today().isoformat()

    log_targets = _resolve_scan_log_uris(
        log_uri=log_uri,
        pick=pick,
        from_date=from_date,
        to_date=to_date,
        usable_only=usable_only,
        refresh=refresh,
    )
    multi_log = len(log_targets) > 1

    rule_expr: str | None = None
    job_query: str | None = None
    if query:
        rule_expr = parse_sql_query(query)
        job_query = query
        console.print(f"SQL: [dim]{query}[/]")
        console.print(f"→   [dim]{rule_expr}[/]\n")
    elif filter_expr:
        rule_expr = filter_expr.strip()
        job_query = filter_expr
        console.print(f"Filter: [dim]{rule_expr}[/]\n")

    if nxdomain and not rule_expr and not rules:
        console.print("Mode: [yellow]NXDOMAIN[/] (no extra rules)\n")

    if save_cert:
        console.print(
            f"Will save hit PEMs → [cyan]{default_certs_dir().resolve()}[/]\n"
        )

    if require_br_icann:
        console.print(
            "Mode: [yellow]BR ICANN PSL[/] — skip certs with PRIVATE DOMAINS suffixes\n"
        )

    db = Database(db_path) if db_path else Database()
    try:
        base_opts = ScanOptions(
            log_uri="",
            target_count=target,
            batch_size=batch_size,
            delay=delay,
            query=rule_expr,
            job_query=job_query,
            rules_file=str(rules) if rules else None,
            nxdomain_mode=nxdomain,
            after_date=after_date,
            save_cert=save_cert,
            resume=not no_resume,
            verbose=verbose,
            trust_env=use_env_proxy and proxy is None,
            proxy=proxy,
            require_br_icann=require_br_icann,
        )

        if multi_log and interval_from and interval_to:
            session_id: int
            global_known: set[str]
            if not no_resume:
                row = db.find_running_session(
                    interval_from,
                    interval_to,
                    job_query,
                    nxdomain,
                )
                if row:
                    session_id = int(row["id"])
                    global_known = db.known_domains_for_session(session_id)
                    console.print(
                        f"[cyan]Resuming session #{session_id}[/] "
                        f"({len(global_known)} unique hits so far)\n"
                    )
                else:
                    session_id = db.create_session(
                        interval_from,
                        interval_to,
                        target,
                        job_query,
                        nxdomain,
                    )
                    global_known = set()
            else:
                session_id = db.create_session(
                    interval_from,
                    interval_to,
                    target,
                    job_query,
                    nxdomain,
                )
                global_known = set()

            by_operator = group_targets_by_operator(log_targets)
            coordinator = IntervalScanCoordinator(
                db,
                console,
                session_id=session_id,
                global_target=target,
                global_known=global_known,
            )
            coordinator.run(by_operator, base_opts, concurrency)
        else:
            target_log = log_targets[0]
            scanner = Scanner(db=db, console=console)
            scanner.run(
                ScanOptions(
                    log_uri=target_log.uri,
                    target_count=target,
                    batch_size=batch_size,
                    delay=delay,
                    query=rule_expr,
                    job_query=job_query,
                    rules_file=str(rules) if rules else None,
                    nxdomain_mode=nxdomain,
                    after_date=after_date,
                    save_cert=save_cert,
                    resume=not no_resume,
                    verbose=verbose,
                    trust_env=use_env_proxy and proxy is None,
                    proxy=proxy,
                    require_br_icann=require_br_icann,
                )
            )
    except SystemExit:
        raise typer.Exit(1)
    finally:
        db.close()


@app.command("check-br")
def cmd_check_br(
    domain: list[str] = typer.Option(
        [], "--domain", "-d", help="DNS name to check (repeatable)"
    ),
    pem: Optional[Path] = typer.Option(
        None, "--pem", help="Certificate PEM file to check all SAN DNS names"
    ),
    log_uri: Optional[str] = typer.Option(
        None, "--log-uri", help="CT log URL (with --log-index)"
    ),
    log_index: Optional[int] = typer.Option(
        None, "--log-index", help="Fetch this CT entry and check its certificate"
    ),
    refresh_psl: bool = typer.Option(
        False, "--refresh-psl", help="Re-download public_suffix_list.dat"
    ),
    use_env_proxy: bool = typer.Option(False, "--use-env-proxy"),
    proxy: Optional[str] = typer.Option(None, "--proxy"),
):
    """
    Check whether certificate DNS names use PSL **ICANN DOMAINS** (BR audit helper).

    Names whose public suffix appears only under **PRIVATE DOMAINS** in the
    Mozilla PSL (e.g. blogspot.com, github.io) are reported as non-compliant.
    """
    if refresh_psl:
        load_psl(force_refresh=True)
        get_br_icann_checker.cache_clear()

    from ctscan.psl.loader import psl_cache_path

    checker = get_br_icann_checker()
    console.print(f"[dim]PSL cache: {psl_cache_path()}[/]\n")

    exit_code = 0

    if pem:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import Encoding

        from ctscan.ct.x509_parse import parse_der_certificate

        der = pem.read_bytes()
        try:
            cert_obj = x509.load_pem_x509_certificate(der, default_backend())
            der = cert_obj.public_bytes(encoding=Encoding.DER)
        except Exception as exc:
            console.print(f"[red]Invalid PEM:[/] {exc}")
            raise typer.Exit(1)
        rec = parse_der_certificate(log_index or 0, der)
        result = checker.check_cert(rec)
        _print_cert_br_check(result)
        if not result.all_ok:
            exit_code = 1

    elif log_uri and log_index is not None:
        uri = log_uri.rstrip("/") + "/"
        with CtClient(
            uri, trust_env=use_env_proxy and proxy is None, proxy=proxy
        ) as ct:
            raw = ct.get_entries(log_index, log_index)
            if not raw:
                console.print("[red]get-entries returned no data[/]")
                raise typer.Exit(1)
            rec = ct.parse_entry_at_index(log_index, raw[0])
            if not rec:
                console.print("[red]Could not parse certificate from CT entry[/]")
                raise typer.Exit(1)
            result = checker.check_cert(rec)
            _print_cert_br_check(result)
            if not result.all_ok:
                exit_code = 1

    elif domain:
        for name in domain:
            r = checker.check_name(name)
            ok = r.br_icann_ok
            if ok is True:
                console.print(f"[green]PASS[/] {name}")
            elif ok is False:
                console.print(f"[red]FAIL[/] {name}")
                exit_code = 1
            else:
                console.print(f"[yellow]SKIP[/] {name} — {r.reason}")
            console.print(
                f"  suffix={r.public_suffix or '—'} "
                f"section={r.psl_section or '—'} · {r.reason}"
            )
    else:
        console.print(
            "[red]Specify --domain, --pem, or --log-uri with --log-index[/]"
        )
        raise typer.Exit(1)

    raise typer.Exit(exit_code)


@app.command("scts")
def cmd_scts(
    pem: Path = typer.Option(..., "--pem", help="Certificate PEM or DER file"),
    refresh: bool = typer.Option(
        False, "--refresh", help="Refresh the online CT log list cache"
    ),
    show_contacts: bool = typer.Option(
        False,
        "--show-contacts",
        help="Include operator contact emails from the log list",
    ),
):
    """
    Show which CT logs issued the embedded SCTs in a certificate.

    Matches each SCT ``log_id`` against ``all_logs_list.json`` and reports
    operator, log state, validity period, and URL when known.
    """
    der = load_cert_der(pem)
    cert_info = parse_der_certificate(0, der)
    console.print(
        f"Certificate: [cyan]{cert_info.subject_cn}[/] "
        f"({cert_info.issuer_org})"
    )
    console.print(
        f"Validity: [dim]{cert_info.not_before}[/] → {cert_info.not_after}\n"
    )

    scts = extract_scts_from_der(der)
    if not scts:
        console.print(
            "[red]No embedded SCTs found[/] in certificate extensions "
            "(OID 1.3.6.1.4.1.11129.2.4.2)."
        )
        raise typer.Exit(1)

    log_index, source = fetch_ct_log_index(force_refresh=refresh)
    if source != "live":
        console.print(f"[dim]Log list source: {source}[/]\n")
    if not log_index:
        console.print(
            "[yellow]Log list index unavailable.[/] "
            "Run [cyan]ctscan scts --pem ... --refresh[/] when online.\n"
        )

    results = lookup_scts(scts, log_index)
    unknown = sum(1 for r in results if not r.matched)

    table = Table(title=f"Embedded SCTs ({len(results)})")
    table.add_column("#", justify="right")
    table.add_column("SCT time")
    table.add_column("Operator")
    if show_contacts:
        table.add_column("Contact")
    table.add_column("Log")
    table.add_column("State")
    table.add_column("State since")
    table.add_column("Period")
    table.add_column("Kind")
    table.add_column("URL")

    for i, row in enumerate(results, 1):
        period = "—"
        if row.period_start != "—" or row.period_end != "—":
            period = f"{row.period_start} ~ {row.period_end}"
        cells = [
            str(i),
            row.sct.timestamp,
            row.operator if row.matched else "[unknown]",
        ]
        if show_contacts:
            cells.append(row.operator_contact if row.matched else "—")
        cells.extend(
            [
                row.description if row.matched else "—",
                row.state if row.matched else "—",
                row.state_timestamp if row.matched else "—",
                period if row.matched else "—",
                row.log_kind if row.matched else "—",
                _truncate(row.url if row.matched else "—", 48),
            ]
        )
        style = None if row.matched else "red"
        table.add_row(*cells, style=style)

    console.print(table)
    console.print("\n[bold]Log IDs[/]")
    for i, row in enumerate(results, 1):
        known = "matched" if row.matched else "unknown"
        console.print(
            f"  {i}. [{known}] [dim]{row.sct.log_id_b64}[/] "
            f"({row.sct.extension}, {row.sct.hash_algorithm})"
        )

    if unknown:
        console.print(
            f"\n[yellow]{unknown} SCT(s) not found in log list.[/] "
            "Try [cyan]--refresh[/] or the log may be outside the cached list."
        )
        raise typer.Exit(1)


def _resolve_target_root(
    pem: Path | None,
    der_path: Path | None,
    fingerprint: str | None,
) -> tuple[bytes | None, str]:
    """Return (root DER or None, normalized SHA-256 fingerprint)."""
    if sum(p is not None for p in (pem, der_path, fingerprint)) != 1:
        console.print(
            "[red]Specify exactly one of:[/] [cyan]--pem[/], [cyan]--der[/], "
            "or [cyan]--fingerprint[/]"
        )
        raise typer.Exit(1)

    if pem is not None:
        root_der = load_cert_der(pem)
        return root_der, cert_sha256_fingerprint(root_der)
    if der_path is not None:
        root_der = load_cert_der(der_path)
        return root_der, cert_sha256_fingerprint(root_der)
    assert fingerprint is not None
    fp = normalize_fingerprint(fingerprint)
    if len(fp) != 64:
        console.print("[red]--fingerprint must be a SHA-256 hex digest (64 hex chars)[/]")
        raise typer.Exit(1)
    return None, fp


def _log_has_root(
    roots: list[bytes],
    target_der: bytes | None,
    target_fp: str,
) -> bool:
    if target_der is not None:
        return root_matches(target_der, roots)
    return any(cert_sha256_fingerprint(r) == target_fp for r in roots)


def _make_roots_client(
    log_uri: str,
    *,
    use_env_proxy: bool,
    proxy: str | None,
) -> CtClient:
    return CtClient(
        log_uri,
        timeout=default_roots_timeout(),
        trust_env=use_env_proxy and proxy is None,
        proxy=proxy,
        retries=2,
    )


def _progress_label(text: str, max_len: int = 48) -> str:
    return _truncate(text, max_len)


@app.command("roots")
def cmd_roots(
    log_uri: Optional[str] = typer.Option(
        None, "--log-uri", help="CT log URL (omit with --all-logs)"
    ),
    all_logs: bool = typer.Option(
        False,
        "--all-logs",
        help="Query every log from the cached log list (not just one --log-uri)",
    ),
    usable_only: bool = typer.Option(
        True,
        "--usable-only/--include-all-states",
        help="When using --all-logs, skip non-usable logs",
    ),
    refresh: bool = typer.Option(
        False, "--refresh", help="Refresh the online CT log list cache"
    ),
    use_env_proxy: bool = typer.Option(False, "--use-env-proxy"),
    proxy: Optional[str] = typer.Option(None, "--proxy"),
    delay: float = typer.Option(
        0.05, "--delay", help="Delay between log requests (seconds)"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Print one line per log as it is queried"
    ),
):
    """List accepted root certificates from CT log(s) via ``ct/v1/get-roots``."""
    import time

    if not log_uri and not all_logs:
        console.print("[red]Specify --log-uri or --all-logs[/]")
        raise typer.Exit(1)
    if log_uri and all_logs:
        console.print("[red]Use either --log-uri or --all-logs, not both[/]")
        raise typer.Exit(1)

    targets: list[tuple[str, str]] = []
    if log_uri:
        targets.append((log_uri.rstrip("/") + "/", "single log"))
    else:
        logs, source = fetch_ct_logs(force_refresh=refresh)
        if source != "live":
            console.print(f"[dim]Log list source: {source}[/]\n")
        if not logs:
            console.print("[red]No CT logs available.[/]")
            raise typer.Exit(1)
        for log in logs:
            if usable_only and log.state != "usable":
                continue
            targets.append((log.url.rstrip("/") + "/", log.description))

    total = len(targets)
    console.print(
        f"Querying [cyan]ct/v1/get-roots[/] for {total} log(s) "
        f"(45s read timeout per log)…\n"
    )

    def _query_one(i: int, uri: str, label: str) -> list[bytes] | None:
        try:
            with _make_roots_client(
                uri, use_env_proxy=use_env_proxy, proxy=proxy
            ) as ct:
                return ct.get_roots()
        except Exception as exc:
            console.print(f"[red]Failed[/] {_progress_label(label)}: {exc}")
            return None

    if total > 1:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Fetching roots", total=total)
            for i, (uri, label) in enumerate(targets):
                progress.update(
                    task,
                    description=f"[{i + 1}/{total}] {_progress_label(label)}",
                )
                roots = _query_one(i, uri, label)
                if verbose and roots is not None:
                    console.print(
                        f"  [{i + 1}/{total}] {_progress_label(label)} — "
                        f"{len(roots)} root(s)"
                    )
                progress.advance(task)
                _print_roots_block(i, total, uri, label, roots, delay)
    else:
        for i, (uri, label) in enumerate(targets):
            console.print(f"Fetching [cyan]{uri}[/] …")
            roots = _query_one(i, uri, label)
            if verbose and roots is not None:
                console.print(
                    f"  [{i + 1}/{total}] {_progress_label(label)} — "
                    f"{len(roots)} root(s)"
                )
            _print_roots_block(i, total, uri, label, roots, delay)


def _print_roots_block(
    i: int,
    total: int,
    uri: str,
    label: str,
    roots: list[bytes] | None,
    delay: float,
) -> None:
    import time

    if roots is None:
        if i < total - 1:
            time.sleep(delay)
        return

    if total > 1:
        console.print(f"\n[bold]{label}[/]\n[dim]{uri}[/]")
    if not roots:
        console.print("[yellow]No roots returned[/]")
    else:
        table = Table()
        table.add_column("#", justify="right")
        table.add_column("Subject CN")
        table.add_column("Subject O")
        table.add_column("SHA-256")
        for n, der in enumerate(roots, 1):
            info = describe_root(der)
            table.add_row(
                str(n),
                info["subject_cn"],
                info["subject_org"],
                info["fingerprint_sha256"],
            )
        console.print(table)
        console.print(f"[dim]{len(roots)} root(s)[/]")

    if i < total - 1:
        time.sleep(delay)


@app.command("check-root")
def cmd_check_root(
    pem: Optional[Path] = typer.Option(
        None, "--pem", help="Your root CA certificate (PEM)"
    ),
    der_path: Optional[Path] = typer.Option(
        None, "--der", help="Your root CA certificate (DER)"
    ),
    fingerprint: Optional[str] = typer.Option(
        None,
        "--fingerprint",
        help="SHA-256 fingerprint of your root (hex, with or without colons)",
    ),
    usable_only: bool = typer.Option(
        True,
        "--usable-only/--include-all-states",
        help="Only check logs marked usable in the log list",
    ),
    missing_only: bool = typer.Option(
        False,
        "--missing-only",
        help="Print only logs that do not include your root",
    ),
    refresh: bool = typer.Option(
        False, "--refresh", help="Refresh the online CT log list cache"
    ),
    use_env_proxy: bool = typer.Option(False, "--use-env-proxy"),
    proxy: Optional[str] = typer.Option(None, "--proxy"),
    delay: float = typer.Option(
        0.05, "--delay", help="Delay between get-roots requests (seconds)"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Print one line per log as it is checked"
    ),
    show_contacts: bool = typer.Option(
        False,
        "--show-contacts",
        help="Include operator contact emails from the log list",
    ),
):
    """
    Check which CT logs accept your root (``ct/v1/get-roots``).

    Reports logs that include your root and logs where it is missing.
    """
    import time

    target_der, target_fp = _resolve_target_root(pem, der_path, fingerprint)
    if target_der is not None:
        info = describe_root(target_der)
        console.print(
            f"Target root: [cyan]{info['subject_cn']}[/] "
            f"({info['subject_org']})"
        )
    console.print(f"SHA-256: [dim]{target_fp}[/]\n")

    logs, source = fetch_ct_logs(force_refresh=refresh)
    if source != "live":
        console.print(f"[dim]Log list source: {source}[/]\n")
    if not logs:
        console.print("[red]No CT logs available.[/]")
        raise typer.Exit(1)

    if usable_only:
        logs = [log for log in logs if log.state == "usable"]
        if not logs:
            console.print("[red]No usable logs in list.[/] Try --include-all-states.")
            raise typer.Exit(1)

    contacts_map: dict[str, str] = {}
    if show_contacts:
        operators, op_source = fetch_ct_operators(force_refresh=refresh)
        contacts_map = operator_contact_map(operators)
        if op_source in ("builtin", "empty"):
            console.print(
                "[yellow]Operator emails unavailable without log list cache.[/] "
                "Try [cyan]--refresh --show-contacts[/]\n"
            )

    total = len(logs)
    console.print(
        f"Querying [cyan]ct/v1/get-roots[/] for {total} log(s) "
        f"(45s read timeout per log)…\n"
    )

    table = Table(title="CT log root coverage")
    table.add_column("Operator")
    if show_contacts:
        table.add_column("Contact")
    table.add_column("Log")
    table.add_column("State")
    table.add_column("Has root")
    table.add_column("Roots", justify="right")
    table.add_column("Note")

    present = 0
    missing: list = []
    errors: list[str] = []

    progress_ctx: Progress | None = None
    task = None
    if total > 1:
        progress_ctx = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )

    def _process_log(i: int, log) -> None:
        nonlocal present
        uri = log.url.rstrip("/") + "/"
        ok = True
        try:
            with _make_roots_client(
                uri, use_env_proxy=use_env_proxy, proxy=proxy
            ) as ct:
                roots = ct.get_roots()
            has = _log_has_root(roots, target_der, target_fp)
            note = ""
        except Exception as exc:
            ok = False
            has = False
            roots = []
            note = str(exc)[:80]
            errors.append(log.description)

        if ok:
            if has:
                present += 1
                status = "yes"
            else:
                missing.append(log)
                status = "no"
        else:
            status = "error"

        if verbose:
            roots_n = str(len(roots)) if roots or status != "error" else "—"
            console.print(
                f"  [{i + 1}/{total}] {_progress_label(log.description)} "
                f"— {status} ({roots_n} roots)"
            )

        if missing_only and status == "yes":
            return

        style = None
        if status == "yes":
            style = "green"
        elif status == "no":
            style = "red"
        elif status == "error":
            style = "yellow"

        row = [log.operator]
        if show_contacts:
            row.append(contacts_map.get(log.operator, "—"))
        row.extend(
            [
                log.description,
                log.state,
                status,
                str(len(roots)) if roots or status != "error" else "—",
                note,
            ]
        )
        table.add_row(*row, style=style)

    if total > 1:
        with progress_ctx as progress:
            task = progress.add_task("Checking roots", total=total)
            for i, log in enumerate(logs):
                progress.update(
                    task,
                    description=(
                        f"[{i + 1}/{total}] {_progress_label(log.description)}"
                    ),
                )
                _process_log(i, log)
                progress.advance(task)
                if i < total - 1:
                    time.sleep(delay)
    else:
        for i, log in enumerate(logs):
            console.print(f"Checking {_progress_label(log.description)} …")
            _process_log(i, log)
            if i < total - 1:
                time.sleep(delay)

    console.print(table)
    console.print(
        f"\n[bold]Summary:[/] {present}/{len(logs)} log(s) include your root."
    )
    if missing:
        console.print(f"[red]Missing ({len(missing)}):[/]")
        for log in missing:
            line = f"  · {log.description}"
            if show_contacts:
                line += f" — {contacts_map.get(log.operator, '—')}"
            console.print(line)
    if errors:
        console.print(f"[yellow]Errors ({len(errors)}):[/] use --delay or check network")

    raise typer.Exit(1 if missing else 0)


@app.command("save-certs")
def cmd_save_certs(
    job_id: Optional[int] = typer.Option(
        None, "--job-id", help="Job ID (default: latest completed job)"
    ),
    certs_dir: Optional[Path] = typer.Option(
        None, "--certs-dir", help="PEM output directory (default ~/.ctscan/certs)"
    ),
    delay: float = typer.Option(
        0.05, "--delay", help="Delay between get-entries calls (seconds)"
    ),
    use_env_proxy: bool = typer.Option(
        False, "--use-env-proxy", help="Use proxy from environment variables"
    ),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Explicit proxy URL"),
    db_path: Optional[Path] = typer.Option(None, "--db", help="SQLite path"),
):
    """Backfill PEM files for existing hits (re-fetch entries by log_index)."""
    import time

    from ctscan.ct.http_util import format_connect_error_hint

    out_dir = certs_dir or default_certs_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    db = Database(db_path) if db_path else Database()
    try:
        jid = job_id
        if jid is None:
            jid = db.get_latest_completed_job_id()
            if jid is None:
                console.print(
                    "[red]No completed job.[/] Use [cyan]--job-id[/] or finish a scan first."
                )
                raise typer.Exit(1)
            console.print(f"[dim]Backfilling PEMs for job #{jid}[/]")

        job = db.get_job(jid)
        if not job:
            console.print(f"[red]Job #{jid} not found.[/]")
            raise typer.Exit(1)

        indices = db.list_match_log_indices(jid)
        if not indices:
            console.print(f"[yellow]Job #{jid} has no matches.[/]")
            raise typer.Exit(0)

        skipped = written = failed = 0
        log_uri = job["log_uri"]
        console.print(
            f"{len(indices)} log_index value(s) → [cyan]{out_dir.resolve()}[/]\n"
        )

        with CtClient(
            log_uri,
            trust_env=use_env_proxy and proxy is None,
            proxy=proxy,
        ) as ct:
            for idx in indices:
                path = pem_path_for_index(out_dir, idx)
                if path.exists():
                    skipped += 1
                    continue
                try:
                    raw = ct.get_entries(idx, idx)
                    if not raw:
                        failed += 1
                        console.print(f"[yellow]  [{idx}] empty get-entries[/]")
                        continue
                    rec = ct.parse_entry_at_index(idx, raw[0])
                    if rec and save_pem_from_record(rec, out_dir):
                        written += 1
                        console.print(f"[dim]  [{idx}] saved[/]")
                    else:
                        failed += 1
                        console.print(
                            f"[yellow]  [{idx}] parse failed or missing DER[/]"
                        )
                except Exception as e:
                    failed += 1
                    console.print(f"[yellow]  [{idx}] failed: {e}[/]")
                time.sleep(delay)

        console.print(
            f"\n[green]Done.[/] wrote {written}, skipped {skipped} (already exist), "
            f"failed {failed}"
        )
    finally:
        db.close()


@app.command("dump-entries")
def cmd_dump_entries(
    log_uri: str = typer.Option(..., "--log-uri", help="CT log URL"),
    output: Path = typer.Option(
        Path("ct_entries.jsonl"),
        "--output",
        "-o",
        help="Output JSONL path",
    ),
    start: Optional[int] = typer.Option(
        None, "--start", help="Start log index (inclusive)"
    ),
    end: Optional[int] = typer.Option(None, "--end", help="End log index (inclusive)"),
    batch_size: int = typer.Option(
        200, "--batch-size", help="Entries per get-entries request"
    ),
    use_env_proxy: bool = typer.Option(
        False,
        "--use-env-proxy",
        help="Use HTTP_PROXY/HTTPS_PROXY from environment (default: direct)",
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", help="Explicit proxy URL (overrides environment)"
    ),
):
    """
    Download raw ``ct/v1/get-entries`` JSON for a log index range (no cert parsing).

    Prints current head (tree_size), then prompts for start/end if omitted.
    Writes one JSON object per line (JSONL): {"index": i, "entry": {...}}.
    """
    from ctscan.ct.http_util import format_connect_error_hint

    uri = log_uri.rstrip("/") + "/"
    with CtClient(uri, trust_env=use_env_proxy and proxy is None, proxy=proxy) as ct:
        try:
            tree_size = ct.get_tree_size()
        except httpx.HTTPError as exc:
            console.print(format_connect_error_hint(exc))
            raise typer.Exit(1) from exc

        head = max(0, tree_size - 1)
        console.print(f"CT log head: tree_size={tree_size:,} (max index {head:,})")

        if start is None:
            start = int(typer.prompt("Start index (inclusive)", default="0"))
        if end is None:
            end = int(typer.prompt("End index (inclusive)", default=str(head)))

        if start < 0 or end < start:
            console.print(f"[red]Invalid range:[/] {start}..{end}")
            raise typer.Exit(1)
        if tree_size > 0 and end > head:
            console.print(
                f"[red]End index out of range:[/] {end} (max {head})"
            )
            raise typer.Exit(1)

        try:
            ranges = _iter_entry_ranges(start, end, batch_size)
        except ValueError as exc:
            console.print(f"[red]{exc}[/]")
            raise typer.Exit(1) from exc

        output.parent.mkdir(parents=True, exist_ok=True)
        total = end - start + 1
        console.print(
            f"Downloading {total:,} entries → [cyan]{output.resolve()}[/] "
            f"({len(ranges)} request(s))\n"
        )

        written = 0
        with output.open("w", encoding="utf-8") as f:
            meta = {
                "type": "ctscan_dump_entries",
                "log_uri": uri,
                "tree_size": tree_size,
                "start": start,
                "end": end,
                "batch_size": batch_size,
            }
            f.write(json.dumps(meta, ensure_ascii=False) + "\n")

            for r_start, r_end in ranges:
                entries = ct.get_entries(r_start, r_end)
                if not entries:
                    console.print(
                        f"[yellow]Warning:[/] empty get-entries {r_start}..{r_end}"
                    )
                for i, entry in enumerate(entries):
                    idx = r_start + i
                    f.write(
                        json.dumps({"index": idx, "entry": entry}, ensure_ascii=False)
                        + "\n"
                    )
                    written += 1

        console.print(f"[green]Done.[/] wrote {written:,} JSONL line(s)")


@app.command("parse-dump")
def cmd_parse_dump(
    input_path: Path = typer.Option(..., "--input", "-i", help="Input JSONL from dump-entries"),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write extracted rows to JSONL (default: stdout)",
    ),
    csv_output: Optional[Path] = typer.Option(
        None,
        "--csv",
        help="Write extracted rows to CSV (mutually exclusive with --output and stdout)",
    ),
    export_der_dir: Optional[Path] = typer.Option(
        None,
        "--export-der-dir",
        help="Export leaf certificate DER files to this directory (named <index>.der)",
    ),
    limit: Optional[int] = typer.Option(
        None, "--limit", help="Stop after N parsed entries"
    ),
):
    """
    Parse a dump-entries JSONL and extract:

    - CT timestamp (ms / ISO)
    - leaf certificate DER (base64)

    Writes JSONL rows:
      {"index": 123, "timestamp_ms": 0, "timestamp_utc": "...", "cert_der_b64": "...", ...}
    """
    from ctscan.ct.entry import extract_certificate_der

    if not input_path.is_file():
        console.print(f"[red]Input not found:[/] {input_path}")
        raise typer.Exit(1)

    if csv_output and output:
        console.print("[red]Use either --csv or --output, not both[/]")
        raise typer.Exit(1)

    if export_der_dir:
        export_der_dir.mkdir(parents=True, exist_ok=True)

    out_f = None
    csv_f = None
    csv_writer = None
    try:
        out_f = (output.open("w", encoding="utf-8") if output else None)
        csv_f = (csv_output.open("w", encoding="utf-8", newline="") if csv_output else None)
        if csv_f:
            csv_writer = csv.DictWriter(
                csv_f,
                fieldnames=[
                    "index",
                    "timestamp_ms",
                    "timestamp_utc",
                    "issuer_cn",
                    "issuer_org",
                    "subject_cn",
                    "subject_org",
                    "not_before",
                    "not_after",
                    "domain",
                    "san",
                    "cert_der_b64",
                ],
            )
            csv_writer.writeheader()
        written = 0

        with input_path.open("r", encoding="utf-8") as f:
            first = f.readline()
            if not first:
                console.print("[red]Empty input file[/]")
                raise typer.Exit(1)
            try:
                meta = json.loads(first)
            except json.JSONDecodeError:
                meta = {}

            # If the first line looks like an entry row, treat it as such.
            pending_first_line = None
            if "type" in meta and meta.get("type") == "ctscan_dump_entries":
                pass
            else:
                pending_first_line = first

            def emit(row: dict) -> None:
                nonlocal written
                if csv_writer is not None:
                    csv_writer.writerow(row)
                else:
                    line = json.dumps(row, ensure_ascii=False)
                    if out_f:
                        out_f.write(line + "\n")
                    else:
                        console.print(line, markup=False)
                written += 1

            def handle_line(line: str) -> None:
                if not line.strip():
                    return
                obj = json.loads(line)
                idx = int(obj["index"])
                entry = obj["entry"]
                leaf_b = base64.b64decode(entry["leaf_input"])
                extra_b = base64.b64decode(entry.get("extra_data") or "")
                ts_ms = _parse_ct_leaf_timestamp_ms(leaf_b)
                ts_iso = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).isoformat()
                der = extract_certificate_der(leaf_b, extra_b)
                der_b64 = base64.b64encode(der).decode("ascii")
                cert = parse_der_certificate(idx, der)
                domain = cert.san[0] if cert.san else ""
                san_s = cert.san

                if export_der_dir:
                    (export_der_dir / f"{idx}.der").write_bytes(der)

                emit(
                    {
                        "index": idx,
                        "timestamp_ms": ts_ms,
                        "timestamp_utc": ts_iso,
                        "issuer_cn": cert.issuer_cn,
                        "issuer_org": cert.issuer_org,
                        "subject_cn": cert.subject_cn,
                        "subject_org": cert.subject_org,
                        "not_before": cert.not_before,
                        "not_after": cert.not_after,
                        "domain": domain,
                        "san": ";".join(san_s) if csv_writer is not None else san_s,
                        "cert_der_b64": der_b64,
                    }
                )

            if pending_first_line is not None:
                handle_line(pending_first_line)

            for line in f:
                if limit is not None and written >= limit:
                    break
                try:
                    handle_line(line)
                except Exception as exc:
                    console.print(f"[yellow]Skip line (parse error):[/] {exc}")

        if csv_output:
            console.print(
                f"[green]Done.[/] wrote {written} row(s) → [cyan]{csv_output.resolve()}[/]"
            )
        elif output:
            console.print(
                f"[green]Done.[/] wrote {written} row(s) → [cyan]{output.resolve()}[/]"
            )
        else:
            console.print(f"[dim]Done. wrote {written} row(s).[/]")
    finally:
        if out_f:
            out_f.close()
        if csv_f:
            csv_f.close()


@app.command("status")
def cmd_status(
    db_path: Optional[Path] = typer.Option(None, "--db", help="SQLite path"),
):
    """Show active job and hit statistics."""
    db = Database(db_path) if db_path else Database()
    try:
        job = db.get_active_job()
        total = db.count_matches()
        table = Table(title="ctscan status")
        table.add_column("Field")
        table.add_column("Value")
        table.add_row("Database", str(db.path))
        table.add_row("Total hits", str(total))
        if job:
            table.add_row("Active job", f"#{job['id']}")
            table.add_row("Log URI", job["log_uri"])
            table.add_row("Progress", f"{job['matched_count']}/{job['target_count']}")
            table.add_row("Next end index", str(job["next_end_index"]))
            table.add_row("Status", job["status"])
        else:
            table.add_row("Active job", "none")
        console.print(table)
    finally:
        db.close()


@app.command("export")
def cmd_export(
    output: Path = typer.Option(
        Path("scan_results.csv"), "--output", "-o", help="Output CSV path"
    ),
    job_id: Optional[int] = typer.Option(
        None, "--job-id", help="Export only this job"
    ),
    export_all: bool = typer.Option(
        False,
        "--all",
        help="Export all hits in the database (mutually exclusive with default / --job-id)",
    ),
    db_path: Optional[Path] = typer.Option(None, "--db", help="SQLite path"),
):
    """Export matches to CSV.

    By default exports the **latest completed** job. If none exists, exits with a hint to use --all.
    """
    if export_all and job_id is not None:
        console.print("[red]Cannot use both --all and --job-id[/]")
        raise typer.Exit(1)

    db = Database(db_path) if db_path else Database()
    try:
        if export_all:
            export_job_id: Optional[int] = None
        elif job_id is not None:
            export_job_id = job_id
        else:
            export_job_id = db.get_latest_completed_job_id()
            if export_job_id is None:
                console.print(
                    "[red]No completed job.[/] Finish a scan first, or use "
                    "[cyan]ctscan export --all[/]."
                )
                raise typer.Exit(1)
            console.print(f"[dim]Exporting latest completed job #{export_job_id}[/]")
        count = db.export_csv(output, export_job_id)
        scope = (
            "entire database"
            if export_job_id is None
            else f"job #{export_job_id}"
        )
        console.print(f"Exported {count} row(s) from {scope} → [cyan]{output.resolve()}[/]")
    finally:
        db.close()


def _truncate(s: str | None, max_len: int) -> str:
    if not s:
        return "—"
    s = str(s).replace("\n", " ")
    if len(s) <= max_len:
        return s
    return s[: max_len - 1] + "…"


@app.command("jobs")
def cmd_jobs(
    limit: int = typer.Option(50, "--limit", "-n", help="Maximum rows to list"),
    db_path: Optional[Path] = typer.Option(None, "--db", help="SQLite path"),
):
    """List scan jobs with hit counts."""
    db = Database(db_path) if db_path else Database()
    try:
        rows = db.list_jobs(limit)
        if not rows:
            console.print("[dim]No jobs yet.[/]")
            return
        table = Table(title="ctscan jobs")
        table.add_column("ID", justify="right")
        table.add_column("Status")
        table.add_column("Hits", justify="right")
        table.add_column("Progress", justify="right")
        table.add_column("Query")
        table.add_column("Log")
        table.add_column("Created")
        for r in rows:
            prog = f"{r['matched_count']}/{r['target_count']}"
            table.add_row(
                str(r["id"]),
                r["status"],
                str(r["hit_count"]),
                prog,
                _truncate(r["query"], 36),
                _truncate(r["log_uri"], 40),
                _truncate(r["created_at"], 24),
            )
        console.print(table)
    finally:
        db.close()


@app.command("purge")
def cmd_purge(
    job_id: Optional[int] = typer.Option(
        None, "--job-id", help="Delete this job and its matches"
    ),
    wipe_all: bool = typer.Option(
        False, "--all", help="Clear all matches and scan_jobs"
    ),
    completed_only: bool = typer.Option(
        False,
        "--completed",
        help="Delete all completed jobs and matches (keep running, etc.)",
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
    db_path: Optional[Path] = typer.Option(None, "--db", help="SQLite path"),
):
    """Delete jobs and matches (exactly one of: --job-id / --all / --completed)."""
    flags = sum(
        [
            job_id is not None,
            wipe_all,
            completed_only,
        ]
    )
    if flags != 1:
        console.print(
            "[red]Specify exactly one:[/] [cyan]--job-id ID[/], [cyan]--all[/], "
            "or [cyan]--completed[/]"
        )
        raise typer.Exit(1)

    db = Database(db_path) if db_path else Database()
    try:
        if wipe_all:
            msg = (
                f"Will wipe all jobs and matches in [cyan]{db.path}[/]; "
                "this cannot be undone."
            )
        elif completed_only:
            msg = (
                "Will delete all [bold]completed[/] jobs and their matches "
                "(running jobs are kept)."
            )
        else:
            assert job_id is not None
            job = db.get_job(job_id)
            if not job:
                console.print(f"[red]Job #{job_id} not found.[/]")
                raise typer.Exit(1)
            hits = db.count_matches(job_id)
            msg = f"Will delete job [cyan]#{job_id}[/] and {hits} match(es)."

        if not yes and not typer.confirm(msg + " Continue?", default=False):
            raise typer.Abort()

        if wipe_all:
            db.purge_all()
            console.print("[green]Database wiped.[/]")
        elif completed_only:
            n_m, n_j = db.purge_completed_jobs()
            console.print(
                f"[green]Deleted {n_j} completed job(s) and {n_m} match(es).[/]"
            )
        else:
            assert job_id is not None
            if not db.purge_job(job_id):
                console.print(f"[red]Job #{job_id} not found.[/]")
                raise typer.Exit(1)
            console.print(f"[green]Deleted job #{job_id} and its matches.[/]")
    finally:
        db.close()


@app.command("data-dir")
def cmd_data_dir():
    """Print the default data directory."""
    d = default_data_dir()
    console.print(str(d))
    console.print(f"  database: {d / 'ctscan.db'}")
    console.print(f"  certs:    {d / 'certs'}/")


if __name__ == "__main__":
    app()
