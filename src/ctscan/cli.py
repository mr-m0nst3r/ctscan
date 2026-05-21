"""Typer CLI entrypoint."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.table import Table

from ctscan.ct.log_list import (
    fetch_ct_logs,
    group_logs_by_operator,
    group_logs_by_year,
)
from ctscan.ct.client import CtClient
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


def _resolve_log_uri(log_uri: str | None, pick: bool) -> str:
    if log_uri:
        return log_uri.rstrip("/") + "/"
    if not pick:
        console.print("[red]Specify --log-uri or use --pick to choose interactively[/]")
        raise typer.Exit(1)
    return _interactive_pick_log()


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
        icon = "✓" if log.state == "usable" else "✗"
        console.print(f"  {i:2d}. [{icon}] {log.description}")

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
):
    """List all CT log servers."""
    logs, source = fetch_ct_logs(force_refresh=refresh)
    if source != "live":
        console.print(f"[dim]List source: {source}[/]\n")
    if not logs:
        console.print("[red]No log list available (network failed and no cache).[/]")
        raise typer.Exit(1)

    by_year = group_logs_by_year(logs)
    for year, year_logs in by_year.items():
        console.print(f"\n[bold]=== {year} ===[/]")
        for log in year_logs:
            icon = "✓" if log.state == "usable" else "✗"
            console.print(f"  [{icon}] {log.description}")
            console.print(f"      {log.url}")
            console.print(f"      {log.start} ~ {log.end} | {log.operator} | {log.state}")


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
):
    """Scan a CT log and write matches to SQLite."""
    if query and filter_expr:
        console.print("[red]Cannot use both --query and --filter[/]")
        raise typer.Exit(1)

    uri = _resolve_log_uri(log_uri, pick)

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
        scanner = Scanner(db=db, console=console)
        scanner.run(
            ScanOptions(
                log_uri=uri,
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
